"""
download_models.py — Download missing cross-model comparison models for RQ5.

Run from PowerShell/CMD:
  cd C:\Users\hbui11\Desktop\CPSForge
  python download_models.py

Already downloaded:
  - models/qwen3.5-4b   (primary model — RQ1-RQ4)
  - models/qwen3-1.7b   (within-family scaling)

To download for RQ5 cross-model comparison:
  - models/qwen2.5-3b-instruct   (Qwen, different generation)
  - models/phi-4-mini-instruct   (Microsoft, cross-family)
  - models/smollm3-3b            (HuggingFace, cross-family)

Each model is downloaded from HuggingFace Hub using huggingface_hub.
Total additional download: ~20 GB.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("cpsforge.downloader")

# Models to download: (hf_repo_id, local_path)
_MODELS = [
    ("Qwen/Qwen2.5-3B-Instruct",         "models/qwen2.5-3b-instruct"),
    ("microsoft/Phi-4-mini-instruct",     "models/phi-4-mini-instruct"),
    ("HuggingFaceTB/SmolLM3-3B",          "models/smollm3-3b"),
]

# Already present — skip
_ALREADY_DOWNLOADED = [
    "models/qwen3.5-4b",
    "models/qwen3-1.7b",
]


def check_model_present(local_path: str) -> bool:
    """Return True if model directory exists and contains config.json."""
    p = Path(local_path)
    return p.is_dir() and (p / "config.json").exists()


def download_model(repo_id: str, local_dir: str) -> None:
    """Download a model from HuggingFace Hub to a local directory."""
    from huggingface_hub import snapshot_download

    local_path = Path(local_dir)
    if check_model_present(local_dir):
        logger.info("SKIP: %s already present at %s", repo_id, local_dir)
        return

    logger.info("Downloading %s -> %s ...", repo_id, local_dir)
    local_path.mkdir(parents=True, exist_ok=True)
    try:
        snapshot_download(
            repo_id=repo_id,
            local_dir=str(local_path),
            ignore_patterns=["*.msgpack", "flax_model*", "tf_model*", "rust_model*"],
        )
        logger.info("Downloaded: %s", local_dir)
    except Exception as exc:
        logger.error("Failed to download %s: %s", repo_id, exc)
        raise


def verify_model(local_path: str, repo_id: str) -> bool:
    """Quick sanity check: load tokenizer to verify download integrity."""
    try:
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(local_path, trust_remote_code=True)
        logger.info("Verified: %s (vocab_size=%d)", local_path, tokenizer.vocab_size)
        return True
    except Exception as exc:
        logger.warning("Verification failed for %s: %s", local_path, exc)
        return False


def main() -> None:
    p = argparse.ArgumentParser(description="Download CPSForge cross-model comparison models")
    p.add_argument(
        "--models",
        nargs="+",
        default=None,
        help="Specific models to download (repo_id). Default: all missing.",
    )
    p.add_argument(
        "--verify",
        action="store_true",
        help="Verify downloads by loading tokenizer",
    )
    p.add_argument(
        "--skip-existing",
        action="store_true",
        default=True,
        help="Skip already-downloaded models (default: True)",
    )
    args = p.parse_args()

    try:
        from huggingface_hub import snapshot_download  # noqa: F401
    except ImportError:
        logger.error("huggingface_hub not installed. Run: pip install huggingface_hub")
        sys.exit(1)

    # Check what's already there
    for path in _ALREADY_DOWNLOADED:
        if check_model_present(path):
            logger.info("Already present: %s", path)
        else:
            logger.warning("Expected model not found: %s", path)

    # Download missing models
    filter_repos = set(args.models) if args.models else None
    for repo_id, local_path in _MODELS:
        if filter_repos and repo_id not in filter_repos:
            continue
        download_model(repo_id, local_path)
        if args.verify:
            verify_model(local_path, repo_id)

    # Final status
    print()
    print("=" * 60)
    print("Model status:")
    for repo_id, local_path in _MODELS:
        status = "OK" if check_model_present(local_path) else "MISSING"
        print(f"  [{status}] {local_path}  ({repo_id})")
    for path in _ALREADY_DOWNLOADED:
        status = "OK" if check_model_present(path) else "MISSING"
        print(f"  [{status}] {path}  (pre-existing)")
    print("=" * 60)


if __name__ == "__main__":
    main()
