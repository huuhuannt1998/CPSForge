"""
CPSForge ML Detector Trainer
==============================
Trains OCSVM and point-wise IsolationForest detectors on normal-operation
trace data for use in the adaptation loop and detector comparison.

Unlike the :class:`~cpsforge.adaptation.trainer.SequenceDetectorTrainer`
(which trains one specific IsolationForest on windowed features), this
module provides trainers for all ML-based detector types so they can
participate in the closed-loop adaptation experiments.

Usage::

    from cpsforge.adaptation.ml_trainer import MLDetectorTrainer

    trainer = MLDetectorTrainer(detector_type="ocsvm")
    trainer.fit(normal_windows)
    trainer.save(Path("models/ocsvm_level_control.pkl"))
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)


class MLDetectorTrainer:
    """
    Generic trainer for sklearn-based CPSForge detectors.

    Supports ``ocsvm``, ``isolation_forest``, and ``sequence_model`` types.
    All produce a joblib bundle with keys ``{model, scaler, meta}``.
    """

    def __init__(
        self,
        detector_type: str = "isolation_forest",
        random_state: int = 42,
        **kwargs: Any,
    ) -> None:
        self.detector_type = detector_type
        self.random_state = random_state
        self.extra_params = kwargs
        self.model: Optional[Any] = None
        self.scaler: Optional[Any] = None
        self._meta: Dict[str, Any] = {}

    def fit(
        self,
        normal_windows: List[np.ndarray],
        hard_case_windows: Optional[List[np.ndarray]] = None,
    ) -> Dict[str, Any]:
        """
        Train the detector on normal-operation windows.

        Parameters
        ----------
        normal_windows:
            List of (window_size, n_features) arrays.
        hard_case_windows:
            Optional anomaly windows (used to set contamination for IForest).

        Returns
        -------
        Training metadata dict.
        """
        from sklearn.preprocessing import StandardScaler

        if not normal_windows:
            raise ValueError("No training windows provided")

        # For point-wise detectors, flatten windows to individual points
        if self.detector_type in ("ocsvm", "isolation_forest"):
            X_normal = np.vstack(normal_windows)
        else:
            # Windowed: compute mean+std features per window
            features = []
            for w in normal_windows:
                if w.ndim == 2:
                    features.append(np.concatenate([w.mean(axis=0), w.std(axis=0)]))
                else:
                    features.append(w)
            X_normal = np.stack(features)

        # Fit scaler
        self.scaler = StandardScaler().fit(X_normal)
        X_scaled = self.scaler.transform(X_normal)

        # Build and fit the model
        if self.detector_type == "ocsvm":
            from sklearn.svm import OneClassSVM
            nu = self.extra_params.get("nu", 0.05)
            kernel = self.extra_params.get("kernel", "rbf")
            gamma = self.extra_params.get("gamma", "scale")
            self.model = OneClassSVM(
                kernel=kernel, nu=nu, gamma=gamma
            )

        elif self.detector_type == "isolation_forest":
            from sklearn.ensemble import IsolationForest
            n_estimators = self.extra_params.get("n_estimators", 100)
            # Compute contamination from hard-case fraction
            if hard_case_windows:
                n_hard = sum(len(w) for w in hard_case_windows) if hard_case_windows else 0
                contamination = min(0.49, max(0.01, n_hard / (len(X_scaled) + n_hard)))
            else:
                contamination = "auto"
            self.model = IsolationForest(
                n_estimators=n_estimators,
                contamination=contamination,
                random_state=self.random_state,
            )

        elif self.detector_type == "sequence_model":
            from sklearn.ensemble import IsolationForest
            if hard_case_windows:
                n_hard = len(hard_case_windows)
                contamination = min(0.49, max(0.01, n_hard / (len(X_scaled) + n_hard)))
            else:
                contamination = "auto"
            self.model = IsolationForest(
                n_estimators=100,
                contamination=contamination,
                random_state=self.random_state,
            )
        else:
            raise ValueError(f"Unsupported detector_type: {self.detector_type}")

        self.model.fit(X_scaled)

        self._meta = {
            "detector_type": self.detector_type,
            "n_training_samples": len(X_scaled),
            "n_features": X_scaled.shape[1],
            "n_normal_windows": len(normal_windows),
            "n_hard_case_windows": len(hard_case_windows) if hard_case_windows else 0,
        }

        logger.info(
            "MLDetectorTrainer (%s): trained on %d samples, %d features",
            self.detector_type, len(X_scaled), X_scaled.shape[1],
        )
        return self._meta

    def save(self, path: Path) -> None:
        """Save trained model bundle to disk (joblib format)."""
        import joblib

        if self.model is None:
            raise RuntimeError("Model not trained yet")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        bundle = {
            "model": self.model,
            "scaler": self.scaler,
            "meta": self._meta,
        }
        joblib.dump(bundle, path)
        logger.info("ML detector model saved to %s", path)

    def evaluate(
        self,
        normal_windows: List[np.ndarray],
        anomaly_windows: List[np.ndarray],
        threshold: float = 0.5,
    ) -> Dict[str, float]:
        """Evaluate on labeled data."""
        if self.model is None:
            raise RuntimeError("Model not trained yet")

        def _score(windows: List[np.ndarray]) -> List[float]:
            scores = []
            for w in windows:
                if self.detector_type in ("ocsvm", "isolation_forest"):
                    X = w.reshape(1, -1) if w.ndim == 1 else w
                else:
                    if w.ndim == 2:
                        f = np.concatenate([w.mean(axis=0), w.std(axis=0)])
                    else:
                        f = w
                    X = f.reshape(1, -1)

                if self.scaler is not None:
                    X = self.scaler.transform(X)

                raw = self.model.decision_function(X)
                for r in raw:
                    scores.append(float(np.clip(0.5 - r, 0.0, 1.0)))
            return scores

        normal_scores = _score(normal_windows) if normal_windows else []
        anomaly_scores = _score(anomaly_windows) if anomaly_windows else []

        tp = sum(1 for s in anomaly_scores if s >= threshold)
        fn = sum(1 for s in anomaly_scores if s < threshold)
        fp = sum(1 for s in normal_scores if s >= threshold)
        tn = sum(1 for s in normal_scores if s < threshold)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": (tp + tn) / max(tp + tn + fp + fn, 1),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        }
