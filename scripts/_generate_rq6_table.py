"""Generate RQ6 frontier model comparison table from raw parquet data.

Produces overleaf/sections/table_rq6_frontier.tex with exact numbers
using the same post-hoc ASR computation as generate_tables.py.
"""
import json
import warnings
from pathlib import Path
from collections import defaultdict

warnings.filterwarnings("ignore")
import pandas as pd
pd.set_option('future.no_silent_downcasting', True)

# Import the post-hoc ASR computation from the canonical table generator
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cpsforge.analysis.generate_tables import compute_posthoc_success

DATA_DIR = Path("data/raw/v2_online_mitm_level_control")
OUT_PATH = Path("overleaf/sections/table_rq6_frontier.tex")

SCENE_MAP = {
    "level_control": "Level Control",
    "sorting_weight": "Sort.~Weight",
    "sorting_height_basic": "Sort.~Height",
}
SCENE_ORDER = ["level_control", "sorting_weight", "sorting_height_basic"]
CTX_ORDER = ["minimal", "partial", "full"]

def load_runs():
    """Load all runs, return list of (metadata, dataframe) tuples."""
    runs = []
    for d in sorted(DATA_DIR.iterdir()):
        meta_path = d / "metadata.json"
        parquet_path = d / "unified_steps.parquet"
        if not meta_path.exists() or not parquet_path.exists():
            continue
        with open(meta_path) as f:
            meta = json.load(f)
        df = pd.read_parquet(parquet_path)
        runs.append((meta, df))
    return runs

def compute_cell(dfs):
    """Compute metrics for a cell (list of DataFrames from multiple runs)."""
    n_runs = len(dfs)
    total_proposals = 0
    total_writes = 0
    total_success = 0
    total_shield_blk = 0
    total_llm_blk = 0
    latencies = []

    for df in dfs:
        # Count proposals: rows where parsed_decision == "attack"
        attack_rows = df[df["parsed_decision"] == "attack"]
        n_prop = len(attack_rows)
        total_proposals += n_prop

        # Count executed writes
        n_writes = int((df["write_executed"] == True).sum())
        total_writes += n_writes

        # Post-hoc success (same as generate_tables.py)
        posthoc = compute_posthoc_success(df)
        n_succ = int(posthoc.sum())
        total_success += n_succ

        # Count shield blocks
        n_shield = int(df["shield_decision"].fillna("").eq("block").sum())
        total_shield_blk += n_shield

        # Count LLM defender blocks
        if "llm_defender_blocked" in df.columns:
            n_llm = int(df["llm_defender_blocked"].fillna(False).astype(bool).sum())
        else:
            n_llm = 0
        total_llm_blk += n_llm

        # Latencies
        if "llm_latency_ms" in df.columns:
            lats = df["llm_latency_ms"].dropna()
            latencies.extend(lats.tolist())

    asr = (total_success / total_writes * 100) if total_writes > 0 else 0.0
    avg_lat = sum(latencies) / len(latencies) if latencies else 0
    blk = total_proposals - total_writes

    return {
        "runs": n_runs,
        "proposals": total_proposals,
        "blocked": blk,
        "writes": total_writes,
        "success": total_success,
        "asr": asr,
        "lat_ms": avg_lat,
        "shield_blk": total_shield_blk,
        "llm_blk": total_llm_blk,
    }

def main():
    runs = load_runs()
    print(f"Loaded {len(runs)} total runs")

    # Separate GPT-4o-mini and Qwen2.5-3B base
    gpt_runs = defaultdict(list)  # (scene, context, defense) -> [dfs]
    qwen_runs = defaultdict(list)

    for meta, df in runs:
        model = meta.get("model_variant", "base")
        scene = meta.get("scene_name", "")
        ctx = meta.get("context_level", "")
        defense = meta.get("defense_variant", "none")
        attacker = meta.get("attacker_name", meta.get("attacker_type", "online_mitm"))

        if model == "gpt4o_mini":
            key = (scene, ctx, defense)
            gpt_runs[key].append(df)
        elif model == "base" and attacker == "online_mitm":
            # For Qwen baseline, match FRONTIER conditions
            if defense == "none":
                key = (scene, ctx, defense)
                qwen_runs[key].append(df)
            elif defense in ("llm_defender", "llm_combined") and ctx == "full":
                key = (scene, ctx, defense)
                qwen_runs[key].append(df)

    # For Qwen, limit to 3 runs per cell (matching FRONTIER design)
    for key in qwen_runs:
        if len(qwen_runs[key]) > 3:
            qwen_runs[key] = qwen_runs[key][:3]

    # Print summary
    print(f"\nGPT-4o-mini cells: {len(gpt_runs)}")
    for key, dfs in sorted(gpt_runs.items()):
        print(f"  {key}: {len(dfs)} runs")
    print(f"\nQwen2.5-3B matched cells: {len(qwen_runs)}")
    for key, dfs in sorted(qwen_runs.items()):
        print(f"  {key}: {len(dfs)} runs")

    # Compute all cells
    conditions = []
    # No-defense cells
    for scene in SCENE_ORDER:
        for ctx in CTX_ORDER:
            key = (scene, ctx, "none")
            gpt_cell = compute_cell(gpt_runs.get(key, []))
            qwen_cell = compute_cell(qwen_runs.get(key, []))
            conditions.append((scene, ctx, "none", gpt_cell, qwen_cell))

    # Defense cells (full context only)
    for scene in SCENE_ORDER:
        for defense in ["llm_defender", "llm_combined"]:
            key = (scene, "full", defense)
            gpt_cell = compute_cell(gpt_runs.get(key, []))
            qwen_cell = compute_cell(qwen_runs.get(key, []))
            conditions.append((scene, "full", defense, gpt_cell, qwen_cell))

    # Print human-readable summary
    print("\n" + "=" * 100)
    print("  RQ6: GPT-4o-mini vs Qwen2.5-3B Head-to-Head (Paper Table Numbers)")
    print("=" * 100)
    print(f"{'Scene':<20} {'Condition':<15} | {'GPT-4o-mini':^45} | {'Qwen2.5-3B':^45}")
    print(f"{'':20} {'':15} | {'Prop':>5} {'Wr':>5} {'Suc':>5} {'ASR%':>6} {'Lat(s)':>7} | {'Prop':>5} {'Wr':>5} {'Suc':>5} {'ASR%':>6} {'Lat(s)':>7}")
    print("-" * 100)

    for scene, ctx, defense, gpt, qwen in conditions:
        cond = f"{ctx}/{defense}" if defense != "none" else ctx
        sname = SCENE_MAP.get(scene, scene).replace("~", " ")
        g_lat = f"{gpt['lat_ms']/1000:.1f}" if gpt['lat_ms'] > 0 else "--"
        q_lat = f"{qwen['lat_ms']/1000:.1f}" if qwen['lat_ms'] > 0 else "--"
        print(f"{sname:<20} {cond:<15} | {gpt['proposals']:>5} {gpt['writes']:>5} {gpt['success']:>5} {gpt['asr']:>5.1f}% {g_lat:>7} | {qwen['proposals']:>5} {qwen['writes']:>5} {qwen['success']:>5} {qwen['asr']:>5.1f}% {q_lat:>7}")

    # Generate LaTeX table
    lines = []
    lines.append("% Table RQ6 --- Frontier Model Comparison")
    lines.append("% Generated by: python scripts/_generate_rq6_table.py")
    lines.append("\\begin{table*}[t]")
    lines.append("\\centering")
    lines.append("\\caption{RQ6: Frontier model comparison---GPT-4o-mini (API) vs.\\ Qwen2.5-3B-Instruct (local, 4-bit). " +
                  "No-defense rows (top): online MITM attacker, safety shield always active. " +
                  "Defense rows (bottom): full context, LLM defender uses local Qwen2.5-3B for both models. " +
                  "3~repeats per cell; ASR\\,=\\,Succ./Writes computed post-hoc.}")
    lines.append("\\label{tab:frontier}")
    lines.append("\\small")
    lines.append("\\setlength{\\tabcolsep}{3pt}")
    lines.append("\\begin{tabular}{llr|rrrrr|rrrrr}")
    lines.append("\\toprule")
    lines.append(" & & & \\multicolumn{5}{c|}{\\textbf{GPT-4o-mini}} & \\multicolumn{5}{c}{\\textbf{Qwen2.5-3B}} \\\\")
    lines.append("\\textbf{Scene} & \\textbf{Condition} & \\textbf{N} & \\textbf{Prop.} & \\textbf{Wr.} & \\textbf{Suc.} & \\textbf{ASR\\%} & \\textbf{Lat.(s)} & \\textbf{Prop.} & \\textbf{Wr.} & \\textbf{Suc.} & \\textbf{ASR\\%} & \\textbf{Lat.(s)} \\\\")
    lines.append("\\midrule")

    prev_scene = None
    in_defense = False
    for scene, ctx, defense, gpt, qwen in conditions:
        sname = SCENE_MAP.get(scene, scene)
        cond = ctx.capitalize() if defense == "none" else ("LLM Def." if defense == "llm_defender" else "LLM+Comb.")

        # Add defense separator
        if defense != "none" and not in_defense:
            lines.append("\\midrule")
            lines.append("\\multicolumn{13}{l}{\\textit{Defense active (full context):}} \\\\")
            in_defense = True
            prev_scene = None

        # Scene label: show for first row of each scene group
        if scene != prev_scene:
            if prev_scene is not None and defense == "none":
                lines.append("\\midrule")
            scene_label = sname
            prev_scene = scene
        else:
            scene_label = ""

        n = max(gpt["runs"], qwen["runs"])
        g_lat = f"{gpt['lat_ms']/1000:.1f}" if gpt['lat_ms'] > 0 else "--"
        q_lat = f"{qwen['lat_ms']/1000:.1f}" if qwen['lat_ms'] > 0 else "--"

        row = (f"{scene_label} & {cond} & {n} "
               f"& {gpt['proposals']} & {gpt['writes']} & {gpt['success']} & {gpt['asr']:.1f} & {g_lat} "
               f"& {qwen['proposals']} & {qwen['writes']} & {qwen['success']} & {qwen['asr']:.1f} & {q_lat} \\\\")
        lines.append(row)

    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append("\\vspace{2pt}")
    lines.append("\\noindent\\footnotesize{3 repeats per cell; ASR computed post-hoc. GPT-4o-mini via OpenAI API; Qwen2.5-3B local inference in 4-bit NF4. LLM defender always uses local Qwen2.5-3B-Instruct.}")
    lines.append("\\end{table*}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n=> Table written to {OUT_PATH}")

if __name__ == "__main__":
    main()
