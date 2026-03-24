#!/usr/bin/env python
"""
Train ML-based detectors (OCSVM, IsolationForest, LSTM-AD) on baseline traces.

Usage:
    python scripts/train_ml_detectors.py --scene level_control
    python scripts/train_ml_detectors.py --scene sorting_weight
    python scripts/train_ml_detectors.py --scene all
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Baseline run IDs (best runs with active process data)
BASELINE_RUNS = {
    "level_control": "data/raw/level_control_baseline/20260319T172014Z_319f1d25",
    "sorting_weight": "data/raw/sorting_weight_baseline/20260319T174329Z_0414f06c",
}

# Feature column prefixes to use for ML training
FEATURE_PREFIXES = ("sensor__", "actuator__", "setpoint__", "feat__")

DETECTOR_TYPES = ("ocsvm", "isolation_forest", "lstm_ad")


def extract_numeric_features(trace: pd.DataFrame) -> np.ndarray:
    """Extract numeric feature columns from a trace DataFrame."""
    feature_cols = [
        c for c in trace.columns
        if any(c.startswith(p) for p in FEATURE_PREFIXES)
    ]
    if not feature_cols:
        raise ValueError(f"No feature columns found. Columns: {list(trace.columns)[:20]}")

    df = trace[feature_cols].copy()

    # Convert booleans to float
    for col in df.columns:
        if df[col].dtype == bool or df[col].dtype == object:
            df[col] = df[col].astype(float)

    # Fill NaN with 0
    df = df.fillna(0.0).astype(np.float32)

    logger.info("Extracted %d feature columns, %d rows", len(feature_cols), len(df))
    return df.values, feature_cols


def make_windows(X: np.ndarray, window_size: int = 20) -> list[np.ndarray]:
    """Create sliding windows from feature matrix."""
    windows = []
    for i in range(len(X) - window_size + 1):
        windows.append(X[i:i + window_size])
    logger.info("Created %d windows of size %d", len(windows), window_size)
    return windows


def train_ocsvm(X: np.ndarray, scene: str, out_dir: Path) -> Path:
    """Train OCSVM on point-wise features."""
    from cpsforge.adaptation.ml_trainer import MLDetectorTrainer

    # Use individual points (each row is a sample)
    windows = [X[i:i+1] for i in range(len(X))]

    trainer = MLDetectorTrainer(detector_type="ocsvm", nu=0.05, kernel="rbf", gamma="scale")
    meta = trainer.fit(windows)

    model_path = out_dir / f"ocsvm_{scene}.pkl"
    trainer.save(model_path)
    logger.info("OCSVM model saved: %s (meta: %s)", model_path, meta)
    return model_path


def train_iforest(X: np.ndarray, scene: str, out_dir: Path) -> Path:
    """Train Isolation Forest on point-wise features."""
    from cpsforge.adaptation.ml_trainer import MLDetectorTrainer

    windows = [X[i:i+1] for i in range(len(X))]

    trainer = MLDetectorTrainer(detector_type="isolation_forest", n_estimators=100)
    meta = trainer.fit(windows)

    model_path = out_dir / f"iforest_{scene}.pkl"
    trainer.save(model_path)
    logger.info("IForest model saved: %s (meta: %s)", model_path, meta)
    return model_path


def train_lstm_ad(X: np.ndarray, scene: str, out_dir: Path, window_size: int = 20) -> Path:
    """Train LSTM Autoencoder on windowed features."""
    from cpsforge.defenders.lstm_ad_detector import LSTMADTrainer

    windows = make_windows(X, window_size)
    if len(windows) < 10:
        raise ValueError(f"Not enough windows ({len(windows)}) for LSTM training. Need at least 10.")

    input_dim = X.shape[1]
    trainer = LSTMADTrainer(
        input_dim=input_dim,
        hidden_dim=32,
        num_layers=1,
        lr=1e-3,
        epochs=50,
        batch_size=min(32, len(windows)),
    )
    results = trainer.fit(windows)
    logger.info("LSTM-AD training: final_loss=%.6f", results["final_loss"])

    threshold = trainer.determine_threshold(windows, percentile=99.0)
    logger.info("LSTM-AD threshold: %.6f", threshold)

    model_path = out_dir / f"lstm_ad_{scene}.pt"
    trainer.save(model_path)
    logger.info("LSTM-AD model saved: %s", model_path)
    return model_path


def update_defender_config(scene: str, detector_type: str, model_path: Path) -> None:
    """Update the defender YAML config to point to the trained model."""
    config_name_map = {
        "ocsvm": f"ocsvm_{scene}",
        "isolation_forest": f"iforest_{scene}",
        "lstm_ad": f"lstm_ad_{scene}",
    }
    config_name = config_name_map[detector_type]
    config_path = Path("configs/defenders") / f"{config_name}.yaml"

    if not config_path.exists():
        logger.warning("Config file not found: %s", config_path)
        return

    with open(config_path) as f:
        data = yaml.safe_load(f)

    # Use relative path from project root
    rel_path = str(model_path).replace("\\", "/")
    data["model_path"] = rel_path

    # For LSTM-AD, also update reconstruction_threshold
    if detector_type == "lstm_ad":
        import torch
        bundle = torch.load(model_path, weights_only=False)
        if bundle.get("threshold") is not None:
            if data.get("parameters") is None:
                data["parameters"] = {}
            data["parameters"]["reconstruction_threshold"] = float(bundle["threshold"])

    with open(config_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    logger.info("Updated config %s → model_path=%s", config_path, rel_path)


def train_scene(scene: str) -> dict:
    """Train all ML detectors for one scene."""
    run_path = BASELINE_RUNS.get(scene)
    if not run_path:
        raise ValueError(f"No baseline run configured for scene: {scene}")

    trace_path = Path(run_path) / "trace.parquet"
    if not trace_path.exists():
        raise FileNotFoundError(f"Trace not found: {trace_path}")

    trace = pd.read_parquet(trace_path)
    logger.info("Loaded trace: %s (%d rows, %d cols)", trace_path, len(trace), len(trace.columns))

    X, feature_cols = extract_numeric_features(trace)
    logger.info("Feature matrix: shape=%s", X.shape)

    out_dir = Path("data/models") / scene
    out_dir.mkdir(parents=True, exist_ok=True)

    results = {}

    # Train OCSVM
    try:
        model_path = train_ocsvm(X, scene, out_dir)
        update_defender_config(scene, "ocsvm", model_path)
        results["ocsvm"] = {"status": "ok", "model_path": str(model_path)}
    except Exception as e:
        logger.error("OCSVM training failed: %s", e)
        results["ocsvm"] = {"status": "error", "error": str(e)}

    # Train IForest
    try:
        model_path = train_iforest(X, scene, out_dir)
        update_defender_config(scene, "isolation_forest", model_path)
        results["isolation_forest"] = {"status": "ok", "model_path": str(model_path)}
    except Exception as e:
        logger.error("IForest training failed: %s", e)
        results["isolation_forest"] = {"status": "error", "error": str(e)}

    # Train LSTM-AD
    try:
        model_path = train_lstm_ad(X, scene, out_dir)
        update_defender_config(scene, "lstm_ad", model_path)
        results["lstm_ad"] = {"status": "ok", "model_path": str(model_path)}
    except Exception as e:
        logger.error("LSTM-AD training failed: %s", e)
        results["lstm_ad"] = {"status": "error", "error": str(e)}

    # Save training summary
    summary = {
        "scene": scene,
        "baseline_run": run_path,
        "n_samples": len(X),
        "n_features": X.shape[1],
        "feature_columns": feature_cols,
        "results": results,
    }
    summary_path = out_dir / "training_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    logger.info("Training summary saved: %s", summary_path)

    return results


def main():
    parser = argparse.ArgumentParser(description="Train ML detectors on baseline traces")
    parser.add_argument("--scene", default="all", help="Scene name or 'all'")
    args = parser.parse_args()

    scenes = list(BASELINE_RUNS.keys()) if args.scene == "all" else [args.scene]

    for scene in scenes:
        logger.info("=" * 60)
        logger.info("Training ML detectors for scene: %s", scene)
        logger.info("=" * 60)
        try:
            results = train_scene(scene)
            for det, info in results.items():
                status = info.get("status", "unknown")
                logger.info("  %s: %s", det, status)
        except Exception as e:
            logger.error("Scene %s failed: %s", scene, e, exc_info=True)


if __name__ == "__main__":
    main()
