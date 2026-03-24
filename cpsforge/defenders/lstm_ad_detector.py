"""
CPSForge LSTM Autoencoder Anomaly Detector
=============================================
A learned anomaly detector based on an LSTM autoencoder trained on
normal-operation sequences.

Architecture
------------
The model is a sequence-to-sequence autoencoder:

    Encoder:  LSTM(input_dim, hidden_dim, num_layers) -> latent
    Decoder:  LSTM(hidden_dim, hidden_dim, num_layers) -> Linear(input_dim)

The encoder compresses a window of ``window_size`` snapshot vectors into a
latent representation.  The decoder reconstructs the original sequence.
During inference, the reconstruction error (MSE per step, averaged over the
window) serves as the anomaly score.

Training
--------
1. Collect normal-operation traces from baseline runs.
2. Extract sliding windows of snapshot feature vectors.
3. Train the autoencoder to minimise reconstruction MSE.
4. Save the model + scaler + threshold via :meth:`LSTMADTrainer.save`.

The saved bundle is loaded at runtime via ``model_path`` in DefenderConfig.

Configuration (via ``parameters`` dict in DefenderConfig YAML)::

    parameters:
      hidden_dim: 32
      num_layers: 1
      reconstruction_threshold: null   # auto-determined from training if null
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

import numpy as np

from cpsforge.core.config import DefenderConfig
from cpsforge.core.models import DetectionEvent, DetectionSeverity, PlantSnapshot
from cpsforge.defenders.base import BaseDetector

logger = logging.getLogger(__name__)


def _snapshot_to_vector(snapshot: PlantSnapshot) -> Optional[np.ndarray]:
    """Extract numeric values from snapshot into a flat feature vector."""
    values: List[float] = []
    for d in (snapshot.sensors, snapshot.actuators, snapshot.setpoints,
              snapshot.derived_features):
        for v in d.values():
            if v is None:
                values.append(0.0)
            else:
                try:
                    values.append(float(v))
                except (TypeError, ValueError):
                    values.append(0.0)
    return np.array(values, dtype=np.float32) if values else None


# ---------------------------------------------------------------------------
# PyTorch model definition (only imported when needed)
# ---------------------------------------------------------------------------

def _build_model(input_dim: int, hidden_dim: int, num_layers: int) -> Any:
    """Build the LSTM autoencoder. Returns a torch.nn.Module."""
    import torch
    import torch.nn as nn

    class LSTMAutoencoder(nn.Module):
        """Sequence-to-sequence LSTM autoencoder for anomaly detection."""

        def __init__(self, input_dim: int, hidden_dim: int, num_layers: int):
            super().__init__()
            self.encoder = nn.LSTM(
                input_dim, hidden_dim, num_layers, batch_first=True
            )
            self.decoder = nn.LSTM(
                hidden_dim, hidden_dim, num_layers, batch_first=True
            )
            self.output_layer = nn.Linear(hidden_dim, input_dim)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            # x: (batch, seq_len, input_dim)
            _, (h, c) = self.encoder(x)
            # Repeat latent for each timestep
            seq_len = x.size(1)
            decoder_input = h[-1:].permute(1, 0, 2).repeat(1, seq_len, 1)
            decoder_out, _ = self.decoder(decoder_input, (h, c))
            reconstruction = self.output_layer(decoder_out)
            return reconstruction

    return LSTMAutoencoder(input_dim, hidden_dim, num_layers)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class LSTMADDetector(BaseDetector):
    """
    LSTM autoencoder anomaly detector.

    Maintains a rolling window of snapshot feature vectors.  When the
    window is full, reconstructs the sequence through the autoencoder and
    computes the mean-squared reconstruction error.  Fires a detection
    event when the error exceeds the configured threshold.
    """

    def __init__(self, config: DefenderConfig) -> None:
        self._config = config
        params = config.parameters or {}

        self._hidden_dim: int = int(params.get("hidden_dim", 32))
        self._num_layers: int = int(params.get("num_layers", 1))
        self._window_size: int = max(2, config.window_size)
        self._threshold: float = config.anomaly_threshold
        self._recon_threshold: Optional[float] = params.get("reconstruction_threshold")

        self._buffer: Deque[np.ndarray] = deque(maxlen=self._window_size)
        self._model: Optional[Any] = None   # torch.nn.Module
        self._scaler: Optional[Any] = None  # sklearn StandardScaler
        self._trained: bool = False
        self._step_count: int = 0
        self._detection_count: int = 0
        self._last_score: float = 0.0
        self._input_dim: Optional[int] = None

        if config.model_path:
            self._try_load_model(Path(config.model_path))
        else:
            logger.info(
                "LSTMADDetector '%s': no model_path — untrained mode.", self.name
            )

    @property
    def name(self) -> str:
        return self._config.name

    def observe(self, snapshot: PlantSnapshot) -> None:
        vec = _snapshot_to_vector(snapshot)
        if vec is not None:
            self._buffer.append(vec)
            if self._input_dim is None:
                self._input_dim = len(vec)

    def detect(self, snapshot: PlantSnapshot) -> List[DetectionEvent]:
        self.observe(snapshot)
        self._step_count += 1

        if not self._trained or len(self._buffer) < self._window_size:
            return []

        score = self._compute_reconstruction_error()
        self._last_score = score

        threshold = self._recon_threshold or self._threshold
        if score < threshold:
            return []

        self._detection_count += 1
        severity = (
            DetectionSeverity.CRITICAL if score > threshold * 3
            else DetectionSeverity.HIGH if score > threshold * 2
            else DetectionSeverity.MEDIUM if score > threshold * 1.5
            else DetectionSeverity.LOW
        )

        return [DetectionEvent(
            timestamp=snapshot.timestamp or datetime.now(timezone.utc),
            run_id=snapshot.run_id,
            detector_name=self.name,
            severity=severity,
            label="lstm_ad_anomaly",
            confidence=float(np.clip(score / (threshold * 3), 0.5, 1.0)),
            explanation=(
                f"LSTM-AD reconstruction error {score:.4f} exceeds threshold "
                f"{threshold:.4f} (window={self._window_size})"
            ),
            affected_tags=(
                list(snapshot.sensors.keys()) + list(snapshot.actuators.keys())
            ),
            step_id=snapshot.step_id,
        )]

    def reset(self) -> None:
        self._buffer.clear()
        self._step_count = 0
        self._detection_count = 0
        self._last_score = 0.0

    def export_state(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "detector_type": "lstm_ad",
            "trained": self._trained,
            "step_count": self._step_count,
            "detection_count": self._detection_count,
            "last_score": self._last_score,
            "window_size": self._window_size,
            "threshold": self._recon_threshold or self._threshold,
            "hidden_dim": self._hidden_dim,
            "num_layers": self._num_layers,
            "model_path": self._config.model_path,
        }

    def load_model(self, path: Path) -> None:
        self._try_load_model(path)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _compute_reconstruction_error(self) -> float:
        """Score the current buffer window via reconstruction MSE."""
        import torch

        window = np.stack(list(self._buffer))  # (window_size, input_dim)

        if self._scaler is not None:
            original_shape = window.shape
            window_scaled = self._scaler.transform(
                window.reshape(-1, original_shape[-1])
            ).reshape(original_shape)
        else:
            window_scaled = window

        x = torch.tensor(window_scaled, dtype=torch.float32).unsqueeze(0)  # (1, W, D)

        self._model.eval()
        with torch.no_grad():
            reconstruction = self._model(x)

        mse = float(torch.nn.functional.mse_loss(reconstruction, x).item())
        return mse

    def _try_load_model(self, path: Path) -> None:
        """
        Load a trained LSTM-AD bundle.

        Expected bundle format (saved by LSTMADTrainer)::

            {
                "model_state_dict": ...,
                "scaler": StandardScaler or None,
                "input_dim": int,
                "hidden_dim": int,
                "num_layers": int,
                "threshold": float,
                "meta": {...}
            }
        """
        try:
            import torch
            bundle = torch.load(path, map_location="cpu", weights_only=False)

            input_dim = bundle["input_dim"]
            hidden_dim = bundle.get("hidden_dim", self._hidden_dim)
            num_layers = bundle.get("num_layers", self._num_layers)

            model = _build_model(input_dim, hidden_dim, num_layers)
            model.load_state_dict(bundle["model_state_dict"])
            model.eval()

            self._model = model
            self._scaler = bundle.get("scaler")
            self._input_dim = input_dim
            self._hidden_dim = hidden_dim
            self._num_layers = num_layers
            self._trained = True

            if bundle.get("threshold") is not None:
                self._recon_threshold = float(bundle["threshold"])

            logger.info(
                "LSTMADDetector '%s': loaded model from %s "
                "(input_dim=%d, hidden=%d, layers=%d, threshold=%.4f)",
                self.name, path, input_dim, hidden_dim, num_layers,
                self._recon_threshold or self._threshold,
            )
        except Exception as exc:
            logger.warning(
                "LSTMADDetector '%s': failed to load model from %s: %s",
                self.name, path, exc,
            )


# ---------------------------------------------------------------------------
# Trainer (used offline for model fitting)
# ---------------------------------------------------------------------------

class LSTMADTrainer:
    """
    Offline trainer for the LSTM autoencoder anomaly detector.

    Usage::

        trainer = LSTMADTrainer(input_dim=8, hidden_dim=32)
        results = trainer.fit(normal_windows)      # list of (W, D) arrays
        threshold = trainer.determine_threshold(normal_windows)
        trainer.save("model.pt")
    """

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 32,
        num_layers: int = 1,
        lr: float = 1e-3,
        epochs: int = 50,
        batch_size: int = 32,
    ) -> None:
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.lr = lr
        self.epochs = epochs
        self.batch_size = batch_size
        self.model: Optional[Any] = None
        self.scaler: Optional[Any] = None
        self.threshold: Optional[float] = None

    def fit(
        self,
        normal_windows: List[np.ndarray],
        scaler: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Train the LSTM autoencoder on normal-operation windows.

        Parameters
        ----------
        normal_windows:
            List of arrays, each shaped ``(window_size, input_dim)``.
        scaler:
            Optional pre-fitted StandardScaler.

        Returns
        -------
        dict with training loss history.
        """
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset

        if not normal_windows:
            raise ValueError("No training windows provided")

        # Fit scaler if needed
        if scaler is None:
            from sklearn.preprocessing import StandardScaler
            all_points = np.vstack(normal_windows)
            scaler = StandardScaler().fit(all_points)
        self.scaler = scaler

        # Scale windows
        scaled = []
        for w in normal_windows:
            scaled.append(scaler.transform(w))
        X = torch.tensor(np.stack(scaled), dtype=torch.float32)

        model = _build_model(self.input_dim, self.hidden_dim, self.num_layers)
        optimizer = torch.optim.Adam(model.parameters(), lr=self.lr)
        criterion = nn.MSELoss()

        dataset = TensorDataset(X, X)
        loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

        loss_history = []
        model.train()
        for epoch in range(self.epochs):
            epoch_loss = 0.0
            for batch_x, batch_y in loader:
                optimizer.zero_grad()
                recon = model(batch_x)
                loss = criterion(recon, batch_y)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item() * batch_x.size(0)
            epoch_loss /= len(X)
            loss_history.append(epoch_loss)

        model.eval()
        self.model = model
        return {"loss_history": loss_history, "final_loss": loss_history[-1]}

    def determine_threshold(
        self,
        normal_windows: List[np.ndarray],
        percentile: float = 99.0,
    ) -> float:
        """
        Compute anomaly threshold from normal data reconstruction errors.

        Uses the specified percentile of reconstruction errors on normal
        data as the detection threshold.
        """
        import torch

        if self.model is None:
            raise RuntimeError("Model not trained yet")

        errors = []
        self.model.eval()
        with torch.no_grad():
            for w in normal_windows:
                if self.scaler is not None:
                    w = self.scaler.transform(w)
                x = torch.tensor(w, dtype=torch.float32).unsqueeze(0)
                recon = self.model(x)
                mse = float(torch.nn.functional.mse_loss(recon, x).item())
                errors.append(mse)

        self.threshold = float(np.percentile(errors, percentile))
        logger.info(
            "LSTM-AD threshold determined: %.4f (p%.0f of %d normal windows)",
            self.threshold, percentile, len(errors),
        )
        return self.threshold

    def save(self, path: Path) -> None:
        """Save trained model bundle to disk."""
        import torch

        if self.model is None:
            raise RuntimeError("Model not trained yet")

        bundle = {
            "model_state_dict": self.model.state_dict(),
            "scaler": self.scaler,
            "input_dim": self.input_dim,
            "hidden_dim": self.hidden_dim,
            "num_layers": self.num_layers,
            "threshold": self.threshold,
            "meta": {
                "epochs": self.epochs,
                "lr": self.lr,
                "batch_size": self.batch_size,
            },
        }
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(bundle, path)
        logger.info("LSTM-AD model saved to %s", path)

    def evaluate(
        self,
        normal_windows: List[np.ndarray],
        anomaly_windows: List[np.ndarray],
        threshold: Optional[float] = None,
    ) -> Dict[str, float]:
        """Evaluate detection performance on labeled windows."""
        import torch

        if self.model is None:
            raise RuntimeError("Model not trained yet")

        t = threshold or self.threshold or 0.5

        def _score(windows: List[np.ndarray]) -> List[float]:
            scores = []
            self.model.eval()
            with torch.no_grad():
                for w in windows:
                    if self.scaler is not None:
                        w = self.scaler.transform(w)
                    x = torch.tensor(w, dtype=torch.float32).unsqueeze(0)
                    recon = self.model(x)
                    mse = float(torch.nn.functional.mse_loss(recon, x).item())
                    scores.append(mse)
            return scores

        normal_scores = _score(normal_windows) if normal_windows else []
        anomaly_scores = _score(anomaly_windows) if anomaly_windows else []

        tp = sum(1 for s in anomaly_scores if s >= t)
        fn = sum(1 for s in anomaly_scores if s < t)
        fp = sum(1 for s in normal_scores if s >= t)
        tn = sum(1 for s in normal_scores if s < t)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": (tp + tn) / max(tp + tn + fp + fn, 1),
            "threshold": t,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        }
