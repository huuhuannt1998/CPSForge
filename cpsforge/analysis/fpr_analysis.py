"""
fpr_analysis.py — Analyze FPR experiment results.

Reads unified_steps.parquet from FPR runs and computes:
  - False positive rate per defense variant per scene
  - Suspicion score distributions on legitimate writes
  - Comparison: base vs finetuned LLM defender

Outputs: LaTeX table for the paper + console summary.

Usage:
  py -3 -m cpsforge.analysis.fpr_analysis
  py -3 -m cpsforge.analysis.fpr_analysis --output overleaf/sections/table_fpr.tex
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fpr_analysis")


def _wilson_ci(successes: int, trials: int, z: float = 1.96) -> Tuple[float, float]:
    """Wilson score confidence interval for a proportion."""
    if trials == 0:
        return (0.0, 0.0)
    p_hat = successes / trials
    denom = 1 + z**2 / trials
    centre = (p_hat + z**2 / (2 * trials)) / denom
    spread = z * ((p_hat * (1 - p_hat) / trials + z**2 / (4 * trials**2)) ** 0.5) / denom
    return (max(0.0, centre - spread), min(1.0, centre + spread))


def find_fpr_runs(base_dir: Path) -> List[Path]:
    """Find all FPR run directories."""
    runs = []
    for scene_dir in base_dir.glob("v2_FPR_*"):
        if scene_dir.is_dir():
            for run_dir in scene_dir.iterdir():
                if run_dir.is_dir():
                    parquet = run_dir / "unified_steps.parquet"
                    if parquet.exists():
                        runs.append(run_dir)
    return sorted(runs)


def analyze_run(run_dir: Path) -> Dict:
    """Analyze a single FPR run."""
    parquet = run_dir / "unified_steps.parquet"
    df = pd.read_parquet(parquet)

    # Count probe proposals (steps where a probe write was generated)
    probes = df[df["action_target_tag"].notna()]
    total_probes = len(probes)

    # Count blocks (false positives on known-legitimate writes)
    blocked = probes[probes["shield_decision"] == "blocked"]
    n_blocked = len(blocked)

    # Breakdown by block stage
    llm_blocked = probes[probes["llm_defender_blocked"] == True] if "llm_defender_blocked" in probes.columns else pd.DataFrame()
    phase_blocked = probes[probes["phase_shield_blocked"] == True] if "phase_shield_blocked" in probes.columns else pd.DataFrame()
    intent_blocked = probes[probes["intent_check_blocked"] == True] if "intent_check_blocked" in probes.columns else pd.DataFrame()

    # Extract metadata
    scene = df["scene"].iloc[0] if "scene" in df.columns else "unknown"
    model = df["model_variant"].iloc[0] if "model_variant" in df.columns else "unknown"
    defense = df["defense_variant"].iloc[0] if "defense_variant" in df.columns else "unknown"

    fpr = n_blocked / total_probes if total_probes > 0 else 0.0
    ci_lo, ci_hi = _wilson_ci(n_blocked, total_probes)

    return {
        "run_dir": str(run_dir.name),
        "scene": scene,
        "model_variant": model,
        "defense_variant": defense,
        "total_probes": total_probes,
        "blocked": n_blocked,
        "allowed": total_probes - n_blocked,
        "fpr": fpr,
        "ci_lo": ci_lo,
        "ci_hi": ci_hi,
        "llm_blocked": len(llm_blocked),
        "phase_blocked": len(phase_blocked),
        "intent_blocked": len(intent_blocked),
    }


def aggregate_results(results: List[Dict]) -> pd.DataFrame:
    """Aggregate FPR results by (scene, model, defense)."""
    df = pd.DataFrame(results)
    if df.empty:
        return df

    grouped = df.groupby(["scene", "model_variant", "defense_variant"]).agg(
        total_probes=("total_probes", "sum"),
        total_blocked=("blocked", "sum"),
        runs=("run_dir", "count"),
    ).reset_index()

    grouped["fpr"] = grouped["total_blocked"] / grouped["total_probes"]
    grouped["fpr_pct"] = (grouped["fpr"] * 100).round(1)

    # Wilson CI on aggregated counts
    cis = grouped.apply(
        lambda row: _wilson_ci(int(row["total_blocked"]), int(row["total_probes"])),
        axis=1,
    )
    grouped["ci_lo"] = [ci[0] for ci in cis]
    grouped["ci_hi"] = [ci[1] for ci in cis]
    grouped["ci_lo_pct"] = (grouped["ci_lo"] * 100).round(1)
    grouped["ci_hi_pct"] = (grouped["ci_hi"] * 100).round(1)

    return grouped


def generate_latex_table(agg: pd.DataFrame, output_path: Path) -> str:
    """Generate LaTeX table for the paper."""
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{False positive rate (FPR) of the LLM defender on known-legitimate writes. "
        r"FPR probes generate controller-consistent writes routed through the defense chain. "
        r"Wilson 95\% CIs reported.}",
        r"\label{tab:fpr}",
        r"\small",
        r"\begin{tabular}{@{}llcrrc@{}}",
        r"\toprule",
        r"\textbf{Scene} & \textbf{Model} & \textbf{Defense} & \textbf{Probes} & \textbf{Blocked} & \textbf{FPR (\%)} \\",
        r"\midrule",
    ]

    scene_names = {
        "level_control": "Level Control",
        "sorting_weight": "Sorting Weight",
        "sorting_height_basic": "Sorting Height",
    }

    prev_scene = None
    for _, row in agg.sort_values(["scene", "model_variant", "defense_variant"]).iterrows():
        scene = scene_names.get(row["scene"], row["scene"])
        if scene != prev_scene and prev_scene is not None:
            lines.append(r"\midrule")
        prev_scene = scene

        model = "Base" if row["model_variant"] == "base" else "Finetuned"
        defense = row["defense_variant"].replace("_", r"\_")
        fpr_str = f"{row['fpr_pct']:.1f} [{row['ci_lo_pct']:.1f}, {row['ci_hi_pct']:.1f}]"

        lines.append(
            f"  {scene} & {model} & {defense} & "
            f"{int(row['total_probes'])} & {int(row['total_blocked'])} & {fpr_str} \\\\"
        )

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])

    tex = "\n".join(lines)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(tex, encoding="utf-8")
    logger.info("LaTeX table written to %s", output_path)
    return tex


def main():
    parser = argparse.ArgumentParser(description="Analyze FPR experiments")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data/raw"),
        help="Base directory for run data",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("overleaf/sections/table_fpr.tex"),
        help="LaTeX table output path",
    )
    args = parser.parse_args()

    runs = find_fpr_runs(args.data_dir)
    if not runs:
        logger.warning("No FPR runs found in %s", args.data_dir)
        logger.info("Run FPR experiments first: py -3 run_fpr_experiments.py")
        return

    logger.info("Found %d FPR runs", len(runs))

    results = []
    for run_dir in runs:
        try:
            result = analyze_run(run_dir)
            results.append(result)
            logger.info(
                "  %s: scene=%s model=%s defense=%s probes=%d blocked=%d FPR=%.1f%%",
                result["run_dir"],
                result["scene"],
                result["model_variant"],
                result["defense_variant"],
                result["total_probes"],
                result["blocked"],
                result["fpr"] * 100,
            )
        except Exception as exc:
            logger.warning("Failed to analyze %s: %s", run_dir, exc)

    if not results:
        logger.warning("No valid results to analyze")
        return

    agg = aggregate_results(results)

    print("\n" + "=" * 70)
    print("FPR RESULTS SUMMARY")
    print("=" * 70)
    print(agg[["scene", "model_variant", "defense_variant", "total_probes", "total_blocked", "fpr_pct"]].to_string(index=False))
    print("=" * 70)

    tex = generate_latex_table(agg, args.output)
    print(f"\nLaTeX table saved to {args.output}")

    # Also save raw results
    raw_path = Path("data/processed/fpr_results.json")
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    with open(raw_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info("Raw results saved to %s", raw_path)


if __name__ == "__main__":
    main()
