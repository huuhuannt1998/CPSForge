"""
Deep cross-analysis: GPT-4o-mini vs Qwen2.5-3B with correct post-hoc ASR.

Replaces _analyze_frontier_all.py which used the broken attack_success column.
Produces detailed per-cell breakdowns, target analysis, timing analysis,
and defense effectiveness comparison.
"""
import json
import warnings
from pathlib import Path
from collections import defaultdict

warnings.filterwarnings("ignore")
import pandas as pd
import numpy as np
pd.set_option('future.no_silent_downcasting', True)

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cpsforge.analysis.generate_tables import compute_posthoc_success

DATA_DIR = Path("data/raw/v2_online_mitm_level_control")

SCENE_NAMES = {
    "level_control": "Level Control",
    "sorting_weight": "Sort. Weight",
    "sorting_height_basic": "Sort. Height",
}
SCENE_ORDER = ["level_control", "sorting_weight", "sorting_height_basic"]
CTX_ORDER = ["minimal", "partial", "full"]
DEFENSE_ORDER = ["none", "llm_defender", "llm_combined"]


def wilson_ci(k, n, z=1.96):
    """Wilson score interval for proportion k/n."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    spread = z * ((p * (1 - p) / n + z**2 / (4 * n**2)) ** 0.5) / denom
    return (max(0, centre - spread), min(1, centre + spread))


def load_all_runs():
    """Load all runs with metadata and compute per-run metrics using post-hoc ASR."""
    runs = []
    for d in sorted(DATA_DIR.iterdir()):
        meta_path = d / "metadata.json"
        pq_path = d / "unified_steps.parquet"
        if not meta_path.exists() or not pq_path.exists():
            continue

        with open(meta_path) as f:
            meta = json.load(f)
        df = pd.read_parquet(pq_path)

        model = meta.get("model_variant", "base")
        scene = meta.get("scene_name", "")
        ctx = meta.get("context_level", "")
        defense = meta.get("defense_variant", "none")
        attacker = meta.get("attacker_name", meta.get("attacker_type", "online_mitm"))

        # Only include online_mitm runs + FRONTIER runs
        if attacker not in ("online_mitm", "frontier_mitm"):
            continue
        if model not in ("base", "gpt4o_mini"):
            continue

        # Compute metrics
        attack_rows = df[df["parsed_decision"] == "attack"]
        n_proposals = len(attack_rows)
        n_writes = int((df["write_executed"] == True).sum())

        posthoc = compute_posthoc_success(df)
        n_success = int(posthoc.sum())

        # Shield blocks
        n_shield_blk = int(df["shield_decision"].fillna("").eq("block").sum()) if "shield_decision" in df.columns else 0

        # LLM defender blocks
        n_llm_blk = 0
        if "llm_defender_blocked" in df.columns:
            n_llm_blk = int(df["llm_defender_blocked"].fillna(False).astype(bool).sum())

        # Phase-aware blocks
        n_phase_blk = 0
        if "phase_shield_blocked" in df.columns:
            n_phase_blk = int(df["phase_shield_blocked"].fillna(False).astype(bool).sum())

        # Intent blocks
        n_intent_blk = 0
        if "intent_check_blocked" in df.columns:
            n_intent_blk = int(df["intent_check_blocked"].fillna(False).astype(bool).sum())

        # Latency
        lat_vals = []
        if "llm_latency_ms" in df.columns:
            lat_vals = df["llm_latency_ms"].dropna().tolist()
        avg_lat_s = np.mean(lat_vals) / 1000 if lat_vals else 0

        # Target tags
        targets = attack_rows["action_target_tag"].dropna().tolist()
        target_counts = defaultdict(int)
        for t in targets:
            target_counts[t] += 1

        # Action types
        action_types = attack_rows["action_type"].dropna().tolist() if "action_type" in attack_rows.columns else []
        type_counts = defaultdict(int)
        for a in action_types:
            type_counts[a] += 1

        # Confidence values
        confs = attack_rows["action_confidence"].dropna().tolist() if "action_confidence" in attack_rows.columns else []

        runs.append({
            "run_id": meta.get("run_id", d.name),
            "model": "GPT-4o-mini" if model == "gpt4o_mini" else "Qwen2.5-3B",
            "model_key": model,
            "scene": scene,
            "context": ctx,
            "defense": defense,
            "n_proposals": n_proposals,
            "n_writes": n_writes,
            "n_success": n_success,
            "n_shield_blk": n_shield_blk,
            "n_llm_blk": n_llm_blk,
            "n_phase_blk": n_phase_blk,
            "n_intent_blk": n_intent_blk,
            "avg_lat_s": avg_lat_s,
            "targets": dict(target_counts),
            "action_types": dict(type_counts),
            "avg_confidence": np.mean(confs) if confs else 0,
            "lat_vals": lat_vals,
        })

    return runs


def section(title):
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}")


def subsection(title):
    print(f"\n  --- {title} ---")


def analyze_no_defense(runs):
    """Detailed no-defense comparison: GPT-4o-mini vs Qwen2.5-3B."""
    section("1. HEAD-TO-HEAD: NO DEFENSE (Post-hoc ASR)")

    nodef = [r for r in runs if r["defense"] == "none"]

    for scene in SCENE_ORDER:
        scene_runs = [r for r in nodef if r["scene"] == scene]
        subsection(f"{SCENE_NAMES[scene]} ({len(scene_runs)} runs)")

        for model_label in ["GPT-4o-mini", "Qwen2.5-3B"]:
            print(f"\n    {model_label}:")
            print(f"    {'Context':<10} {'Runs':>5} {'Prop':>6} {'Writes':>7} {'Succ':>6} {'ASR%':>7} {'VAR%':>7} {'CI_low':>7} {'CI_hi':>7} {'Lat(s)':>7}")
            print(f"    {'-'*10} {'-'*5} {'-'*6} {'-'*7} {'-'*6} {'-'*7} {'-'*7} {'-'*7} {'-'*7} {'-'*7}")

            for ctx in CTX_ORDER:
                cell = [r for r in scene_runs if r["model"] == model_label and r["context"] == ctx]
                if not cell:
                    print(f"    {ctx:<10}   (no data)")
                    continue

                n = len(cell)
                prop = sum(r["n_proposals"] for r in cell)
                writes = sum(r["n_writes"] for r in cell)
                succ = sum(r["n_success"] for r in cell)
                asr = succ / writes * 100 if writes > 0 else 0
                var = writes / prop * 100 if prop > 0 else 0
                ci_lo, ci_hi = wilson_ci(succ, writes)
                avg_lat = np.mean([r["avg_lat_s"] for r in cell])

                print(f"    {ctx:<10} {n:>5} {prop:>6} {writes:>7} {succ:>6} {asr:>7.1f} {var:>7.1f} {ci_lo*100:>7.1f} {ci_hi*100:>7.1f} {avg_lat:>7.1f}")


def analyze_defense(runs):
    """Defense effectiveness against each model."""
    section("2. DEFENSE EFFECTIVENESS")

    for scene in SCENE_ORDER:
        scene_runs = [r for r in runs if r["scene"] == scene]
        subsection(f"{SCENE_NAMES[scene]}")

        for model_label in ["GPT-4o-mini", "Qwen2.5-3B"]:
            model_runs = [r for r in scene_runs if r["model"] == model_label]
            if not model_runs:
                continue

            print(f"\n    {model_label}:")
            print(f"    {'Defense':<15} {'Ctx':<8} {'Runs':>5} {'Prop':>6} {'ShBlk':>6} {'LLMBlk':>7} {'Writes':>7} {'Succ':>6} {'ASR%':>7} {'Prev%':>7}")
            print(f"    {'-'*15} {'-'*8} {'-'*5} {'-'*6} {'-'*6} {'-'*7} {'-'*7} {'-'*6} {'-'*7} {'-'*7}")

            for defense in DEFENSE_ORDER:
                for ctx in CTX_ORDER:
                    cell = [r for r in model_runs if r["defense"] == defense and r["context"] == ctx]
                    if not cell:
                        continue

                    n = len(cell)
                    prop = sum(r["n_proposals"] for r in cell)
                    writes = sum(r["n_writes"] for r in cell)
                    succ = sum(r["n_success"] for r in cell)
                    sh_blk = sum(r["n_shield_blk"] for r in cell)
                    llm_blk = sum(r["n_llm_blk"] for r in cell)
                    asr = succ / writes * 100 if writes > 0 else 0
                    # Prevention: how many proposals did NOT succeed
                    prev = (1 - succ / prop) * 100 if prop > 0 else 100

                    print(f"    {defense:<15} {ctx:<8} {n:>5} {prop:>6} {sh_blk:>6} {llm_blk:>7} {writes:>7} {succ:>6} {asr:>7.1f} {prev:>7.1f}")


def analyze_targets(runs):
    """Target tag analysis by model."""
    section("3. ATTACK TARGET SELECTION")

    nodef = [r for r in runs if r["defense"] == "none"]

    for model_label in ["GPT-4o-mini", "Qwen2.5-3B"]:
        subsection(f"{model_label} — Target Distribution")
        model_runs = [r for r in nodef if r["model"] == model_label]

        for scene in SCENE_ORDER:
            scene_runs = [r for r in model_runs if r["scene"] == scene]
            if not scene_runs:
                continue

            all_targets = defaultdict(int)
            for r in scene_runs:
                for tag, cnt in r["targets"].items():
                    all_targets[tag] += cnt

            total = sum(all_targets.values())
            if total == 0:
                print(f"    {SCENE_NAMES[scene]}: (no proposals)")
                continue

            print(f"    {SCENE_NAMES[scene]} ({total} total proposals):")
            for tag, cnt in sorted(all_targets.items(), key=lambda x: -x[1]):
                pct = cnt / total * 100
                print(f"      {tag:<30} {cnt:>4} ({pct:>5.1f}%)")


def analyze_timing(runs):
    """Latency comparison."""
    section("4. INFERENCE LATENCY COMPARISON")

    nodef = [r for r in runs if r["defense"] == "none"]

    for model_label in ["GPT-4o-mini", "Qwen2.5-3B"]:
        subsection(f"{model_label} — Latency by Context")
        model_runs = [r for r in nodef if r["model"] == model_label]

        print(f"    {'Scene':<20} {'Context':<10} {'Mean(s)':>8} {'Median(s)':>9} {'P95(s)':>8} {'Min(s)':>8} {'Max(s)':>8}")
        print(f"    {'-'*20} {'-'*10} {'-'*8} {'-'*9} {'-'*8} {'-'*8} {'-'*8}")

        for scene in SCENE_ORDER:
            for ctx in CTX_ORDER:
                cell = [r for r in model_runs if r["scene"] == scene and r["context"] == ctx]
                if not cell:
                    continue

                all_lats = []
                for r in cell:
                    all_lats.extend(r["lat_vals"])

                if not all_lats:
                    continue

                lats_s = [l / 1000 for l in all_lats]
                print(f"    {SCENE_NAMES[scene]:<20} {ctx:<10} {np.mean(lats_s):>8.2f} {np.median(lats_s):>9.2f} {np.percentile(lats_s, 95):>8.2f} {np.min(lats_s):>8.2f} {np.max(lats_s):>8.2f}")


def analyze_self_deterrence(runs):
    """Self-deterrence comparison: proposal generation patterns."""
    section("5. SELF-DETERRENCE ANALYSIS (Proposal Generation)")

    nodef = [r for r in runs if r["defense"] == "none"]

    print(f"\n  Proposals per run (max 10 = no self-deterrence):\n")
    print(f"  {'Model':<15} {'Scene':<20} {'Context':<10} {'Runs':>5} {'Prop/Run':>10} {'Min':>5} {'Max':>5} {'Self-Det?':>10}")
    print(f"  {'-'*15} {'-'*20} {'-'*10} {'-'*5} {'-'*10} {'-'*5} {'-'*5} {'-'*10}")

    for model_label in ["GPT-4o-mini", "Qwen2.5-3B"]:
        for scene in SCENE_ORDER:
            for ctx in CTX_ORDER:
                cell = [r for r in nodef if r["model"] == model_label and r["scene"] == scene and r["context"] == ctx]
                if not cell:
                    continue

                props = [r["n_proposals"] for r in cell]
                avg = np.mean(props)
                mn = min(props)
                mx = max(props)
                det = "YES" if avg < 8 else "no"

                print(f"  {model_label:<15} {SCENE_NAMES[scene]:<20} {ctx:<10} {len(cell):>5} {avg:>10.1f} {mn:>5} {mx:>5} {det:>10}")


def analyze_per_run_variance(runs):
    """Per-run variance to assess reproducibility."""
    section("6. RUN-TO-RUN VARIANCE (No Defense)")

    nodef = [r for r in runs if r["defense"] == "none"]

    print(f"\n  {'Model':<15} {'Scene':<20} {'Context':<10} {'R1_ASR':>8} {'R2_ASR':>8} {'R3_ASR':>8} {'StdDev':>8}")
    print(f"  {'-'*15} {'-'*20} {'-'*10} {'-'*8} {'-'*8} {'-'*8} {'-'*8}")

    for model_label in ["GPT-4o-mini", "Qwen2.5-3B"]:
        for scene in SCENE_ORDER:
            for ctx in CTX_ORDER:
                cell = [r for r in nodef if r["model"] == model_label and r["scene"] == scene and r["context"] == ctx]
                if not cell:
                    continue

                per_run_asr = []
                for r in cell:
                    asr = r["n_success"] / r["n_writes"] * 100 if r["n_writes"] > 0 else 0
                    per_run_asr.append(asr)

                # Pad to 3 for display
                while len(per_run_asr) < 3:
                    per_run_asr.append(float('nan'))

                sd = np.nanstd(per_run_asr[:3]) if len([x for x in per_run_asr[:3] if not np.isnan(x)]) > 1 else 0

                r1 = f"{per_run_asr[0]:.1f}" if not np.isnan(per_run_asr[0]) else "N/A"
                r2 = f"{per_run_asr[1]:.1f}" if not np.isnan(per_run_asr[1]) else "N/A"
                r3 = f"{per_run_asr[2]:.1f}" if not np.isnan(per_run_asr[2]) else "N/A"

                print(f"  {model_label:<15} {SCENE_NAMES[scene]:<20} {ctx:<10} {r1:>8} {r2:>8} {r3:>8} {sd:>8.1f}")


def summary_table(runs):
    """Summary comparison table."""
    section("7. SUMMARY: Key Metrics Head-to-Head")

    nodef = [r for r in runs if r["defense"] == "none"]

    print(f"\n  {'Scene':<20} {'Context':<10} | {'GPT Prop':>9} {'ASR%':>6} {'Lat(s)':>7} | {'Qwen Prop':>10} {'ASR%':>6} {'Lat(s)':>7} | {'ΔASR':>6}")
    print(f"  {'-'*20} {'-'*10}-+-{'-'*9}-{'-'*6}-{'-'*7}-+-{'-'*10}-{'-'*6}-{'-'*7}-+-{'-'*6}")

    for scene in SCENE_ORDER:
        for ctx in CTX_ORDER:
            gpt = [r for r in nodef if r["model"] == "GPT-4o-mini" and r["scene"] == scene and r["context"] == ctx]
            qwen = [r for r in nodef if r["model"] == "Qwen2.5-3B" and r["scene"] == scene and r["context"] == ctx]

            def cell_stats(cell):
                if not cell:
                    return 0, 0.0, 0.0
                prop = sum(r["n_proposals"] for r in cell)
                writes = sum(r["n_writes"] for r in cell)
                succ = sum(r["n_success"] for r in cell)
                asr = succ / writes * 100 if writes > 0 else 0
                lat = np.mean([r["avg_lat_s"] for r in cell])
                return prop, asr, lat

            gp, ga, gl = cell_stats(gpt)
            qp, qa, ql = cell_stats(qwen)
            delta = ga - qa

            print(f"  {SCENE_NAMES[scene]:<20} {ctx:<10} | {gp:>9} {ga:>6.1f} {gl:>7.1f} | {qp:>10} {qa:>6.1f} {ql:>7.1f} | {delta:>+6.1f}")


if __name__ == "__main__":
    print("Deep Frontier Cross-Analysis (Post-hoc ASR)")
    print("=" * 80)

    runs = load_all_runs()
    gpt_count = sum(1 for r in runs if r["model_key"] == "gpt4o_mini")
    qwen_count = sum(1 for r in runs if r["model_key"] == "base")
    print(f"\nLoaded {len(runs)} runs: {gpt_count} GPT-4o-mini, {qwen_count} Qwen2.5-3B")

    summary_table(runs)
    analyze_no_defense(runs)
    analyze_self_deterrence(runs)
    analyze_defense(runs)
    analyze_targets(runs)
    analyze_timing(runs)
    analyze_per_run_variance(runs)

    print(f"\n{'='*80}")
    print("  Analysis complete. All ASR values computed via post-hoc success.")
    print(f"{'='*80}")
