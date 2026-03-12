"""
CPSForge Sequence Detector Trainer
=====================================
Offline training and evaluation of the
:class:`~cpsforge.defenders.sequence_model.SequenceModelDetector`.

Strategy
--------
1. **Normal-operation data** is loaded from baseline run traces
   (attack_active = False steps only).
2. **Hard-case data** is loaded from the
   :class:`~cpsforge.adaptation.bank.HardCaseBank` — feature windows
   around attacks that were previously missed or detected too late.
3. Each window of shape ``(window_size, n_features)`` is compressed to a
   1-D feature vector of length ``2 × n_features`` (per-feature mean + std).
4. An :class:`~sklearn.ensemble.IsolationForest` is fitted on the normal
   data with ``contamination`` set by the fraction of hard-case windows
   relative to total windows (floored at 0.01, capped at 0.49).
5. A :class:`~sklearn.preprocessing.StandardScaler` is fitted on the same
   training set and stored with the model.
6. The bundle ``{"model": iso, "scaler": scaler, "meta": {...}}`` is saved
   with :mod:`joblib` to ``<model_dir>/round_<N>/sequence_model.pkl``.

Evaluation
----------
:meth:`evaluate` returns a dict with precision, recall, F1, and accuracy
computed on a supplied labelled set of ``(feature_vector, label)`` pairs
where ``label=1`` means anomalous and ``label=0`` means normal.

All training is fully reproducible when ``random_state`` is set.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# Contamination floor / ceiling for IsolationForest
_CONTAMINATION_MIN = 0.01
_CONTAMINATION_MAX = 0.49


def _windows_to_feature_matrix(windows: Sequence[np.ndarray]) -> np.ndarray:
    """
    Convert a list of ``(T, n_features)`` windows to a 2-D feature matrix
    of shape ``(n_windows, 2 * n_features)``.

    Each window is summarised by per-feature mean and standard deviation.
    """
    rows: List[np.ndarray] = []
    for w in windows:
        w_arr = np.asarray(w, dtype=np.float32)
        if w_arr.ndim == 1:
            w_arr = w_arr.reshape(1, -1)
        if w_arr.shape[0] < 1:
            continue
        rows.append(np.concatenate([w_arr.mean(axis=0), w_arr.std(axis=0)]))
    if not rows:
        raise ValueError("No valid windows provided — cannot build feature matrix.")
    return np.stack(rows).astype(np.float32)


class SequenceDetectorTrainer:
    """
    Trains and evaluates a rolling-window IsolationForest anomaly detector.

    Parameters
    ----------
    random_state:
        Seed for reproducible training.  Passed to both IsolationForest
        and train/test split.
    n_estimators:
        Number of trees in the IsolationForest ensemble
        (100 is a good default).
    """

    def __init__(
        self,
        random_state: int = 42,
        n_estimators: int = 100,
    ) -> None:
        self._random_state = random_state
        self._n_estimators = n_estimators
        self._model: Optional[Any] = None
        self._scaler: Optional[Any] = None
        self._feature_dim: Optional[int] = None
        self._training_meta: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(
        self,
        normal_windows: List[np.ndarray],
        hard_case_windows: Optional[List[np.ndarray]] = None,
    ) -> Dict[str, Any]:
        """
        Train an IsolationForest on *normal_windows* with contamination
        estimated from the hard-case proportion.

        Parameters
        ----------
        normal_windows:
            Windows of shape ``(window_size, n_features)`` from attack-free
            traces.  At least 2 are required.
        hard_case_windows:
            Optional list of windows from missed/late-detected attacks.
            Used purely to estimate the contamination fraction; they are NOT
            included in the training set (IsolationForest is unsupervised on
            normal data only, exploiting the outlier assumption).

        Returns
        -------
        Dict
            Training summary including contamination, n_estimators, and
            feature dimensionality.

        Raises
        ------
        ValueError
            If fewer than 2 normal windows are provided.
        ImportError
            If scikit-learn is not installed.
        """
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except ImportError as exc:
            raise ImportError(
                "scikit-learn is required for SequenceDetectorTrainer. "
                "Install it with: pip install scikit-learn"
            ) from exc

        if len(normal_windows) < 2:
            raise ValueError(
                f"Need at least 2 normal windows for training, "
                f"got {len(normal_windows)}."
            )

        logger.info(
            "Trainer: building feature matrix from %d normal window(s).",
            len(normal_windows),
        )
        X_normal = _windows_to_feature_matrix(normal_windows)
        self._feature_dim = X_normal.shape[1]

        # Estimate contamination from hard-case fraction
        n_hard = len(hard_case_windows) if hard_case_windows else 0
        total = len(normal_windows) + n_hard
        contamination = float(np.clip(n_hard / total, _CONTAMINATION_MIN, _CONTAMINATION_MAX))
        logger.info(
            "Trainer: contamination estimate = %.4f  "
            "(%d hard / %d total windows).",
            contamination,
            n_hard,
            total,
        )

        # Fit scaler on normal data
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_normal)

        # Fit IsolationForest
        iso = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=contamination,
            random_state=self._random_state,
            n_jobs=-1,
        )
        iso.fit(X_scaled)

        self._model = iso
        self._scaler = scaler
        self._training_meta = {
            "n_normal_windows": len(normal_windows),
            "n_hard_case_windows": n_hard,
            "contamination": contamination,
            "n_estimators": self._n_estimators,
            "feature_dim": self._feature_dim,
            "random_state": self._random_state,
        }
        logger.info(
            "Trainer: IsolationForest fitted on %d samples (%d features each).",
            X_scaled.shape[0],
            X_scaled.shape[1],
        )
        return dict(self._training_meta)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        normal_windows: List[np.ndarray],
        anomaly_windows: List[np.ndarray],
        threshold: float = 0.5,
    ) -> Dict[str, float]:
        """
        Evaluate the trained model on held-out normal and anomaly windows.

        Parameters
        ----------
        normal_windows:
            Labelled-0 (normal) windows for evaluation.
        anomaly_windows:
            Labelled-1 (anomalous) windows for evaluation.
        threshold:
            Score cutoff: ``score >= threshold`` → predicted anomaly.

        Returns
        -------
        Dict with keys: precision, recall, f1, accuracy, n_evaluated.

        Raises
        ------
        RuntimeError
            If the model has not been trained yet.
        """
        if self._model is None:
            raise RuntimeError("Trainer: model not fitted — call fit() first.")

        if not normal_windows and not anomaly_windows:
            return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "accuracy": 0.0, "n_evaluated": 0}

        all_windows = list(normal_windows) + list(anomaly_windows)
        labels = [0] * len(normal_windows) + [1] * len(anomaly_windows)

        X = _windows_to_feature_matrix(all_windows)
        if self._scaler is not None:
            X = self._scaler.transform(X)

        # IsolationForest.decision_function: lower = more anomalous
        raw_scores = self._model.decision_function(X)
        pred_scores = np.clip(0.5 - raw_scores, 0.0, 1.0)
        preds = (pred_scores >= threshold).astype(int)
        labels_arr = np.array(labels, dtype=int)

        tp = int(((preds == 1) & (labels_arr == 1)).sum())
        fp = int(((preds == 1) & (labels_arr == 0)).sum())
        fn = int(((preds == 0) & (labels_arr == 1)).sum())
        tn = int(((preds == 0) & (labels_arr == 0)).sum())

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy  = (tp + tn) / len(labels) if labels else 0.0

        return {
            "precision": round(precision, 4),
            "recall":    round(recall, 4),
            "f1":        round(f1, 4),
            "accuracy":  round(accuracy, 4),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "n_evaluated": len(labels),
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Path) -> None:
        """
        Serialise the trained model and scaler to *path* using :mod:`joblib`.

        The saved bundle is a dict::

            {
                "model":  IsolationForest,
                "scaler": StandardScaler (or None),
                "meta":   training_meta dict,
            }

        This format is loaded directly by
        :meth:`~cpsforge.defenders.sequence_model.SequenceModelDetector.load_model`.

        Raises
        ------
        RuntimeError
            If the model has not been trained yet.
        """
        if self._model is None:
            raise RuntimeError("Trainer: nothing to save — call fit() first.")

        import joblib

        path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "model": self._model,
            "scaler": self._scaler,
            "meta": self._training_meta,
        }
        joblib.dump(bundle, path)
        logger.info("Trainer: model bundle saved to %s.", path)

    @classmethod
    def load(cls, path: Path) -> "SequenceDetectorTrainer":
        """
        Load a previously saved trainer bundle from *path*.

        Returns a :class:`SequenceDetectorTrainer` with ``_model`` and
        ``_scaler`` populated and ``_trained`` semantically True.

        Raises
        ------
        FileNotFoundError
            If *path* does not exist.
        """
        import joblib

        if not path.exists():
            raise FileNotFoundError(f"Trainer bundle not found: {path}")

        bundle = joblib.load(path)
        trainer = cls()
        trainer._model = bundle["model"]
        trainer._scaler = bundle.get("scaler")
        trainer._training_meta = bundle.get("meta", {})
        trainer._feature_dim = trainer._training_meta.get("feature_dim")
        logger.info("Trainer: loaded model bundle from %s.", path)
        return trainer

    @property
    def is_trained(self) -> bool:
        """True if a model has been fitted or loaded."""
        return self._model is not None

    @property
    def training_meta(self) -> Dict[str, Any]:
        """Metadata from the last :meth:`fit` call."""
        return dict(self._training_meta)
