"""
Cross-scene FRONTIER analysis: GPT-4o-mini vs Qwen2.5-3B across all 3 scenes.
Analyzes all 45 FRONTIER cells (15 per scene) and compares with Qwen2.5-3B baseline.
"""
import json
import os
import warnings
from pathlib import Path
from collections import defaultdict

warnings.filterwarnings("ignore")
import pandas as pd
pd.set_option('future.no_silent_downcasting', True)

DATA_DIR = Path("data/raw/v2_online_mitm_level_control")
ATTACK_BUDGET = 10

def load_runs():
    """Load all runs, tagged by model_variant."""
    runs = []
    if not DATA_DIR.exists():
        print(f"ERROR: {DATA_DIR} not found")
        return runs
    
    for d in sorted(DATA_DIR.iterdir()):
        meta_path = d / "metadata.json"
        pq_path = d / "unified_steps.parquet"
        if not meta_path.exists() or not pq_path.exists():
            continue
        
        meta = json.loads(meta_path.read_text())
        model = meta.get("model_variant", "unknown")
        scene = meta.get("scene_name", "unknown")
        ctx = meta.get("context_level", "unknown")
        defense = meta.get("defense_variant", "none")
        
        # Read parquet for metrics
        df = pd.read_parquet(pq_path)
        
        n_proposals = int((df["parsed_decision"] == "attack").sum())
        n_valid = int(df["write_executed"].fillna(False).astype(bool).sum())
        n_success = int(df["attack_success"].fillna(False).astype(bool).sum())
        
        # Defense blocking stats
        n_shield_blocked = int(df["shield_decision"].fillna("").eq("blocked").sum()) if "shield_decision" in df.columns else 0
        n_llm_blocked = int(df["llm_defender_blocked"].fillna(False).astype(bool).sum()) if "llm_defender_blocked" in df.columns else 0
        n_phase_blocked = int(df["phase_shield_blocked"].fillna(False).astype(bool).sum()) if "phase_shield_blocked" in df.columns else 0
        n_intent_blocked = int(df["intent_check_blocked"].fillna(False).astype(bool).sum()) if "intent_check_blocked" in df.columns else 0
        
        # Target tags
        targets = df.loc[df["parsed_decision"] == "attack", "action_target_tag"].dropna().tolist()
        target_counts = defaultdict(int)
        for t in targets:
            target_counts[t] += 1
        
        # LLM latency
        llm_lat = df["llm_latency_ms"].dropna()
        avg_latency = float(llm_lat.mean()) if len(llm_lat) > 0 else 0
        
        runs.append({
            "run_id": meta.get("run_id", d.name),
            "model": model,
            "scene": scene,
            "context": ctx,
            "defense": defense,
            "n_proposals": n_proposals,
            "n_valid": n_valid,
            "n_success": n_success,
            "n_shield_blocked": n_shield_blocked,
            "n_llm_blocked": n_llm_blocked,
            "n_phase_blocked": n_phase_blocked,
            "n_intent_blocked": n_intent_blocked,
            "targets": dict(target_counts),
            "avg_latency_ms": avg_latency,
        })
    
    return runs


def print_section(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def analyze_frontier(runs):
    """Analyze GPT-4o-mini FRONTIER results."""
    frontier = [r for r in runs if r["model"] == "gpt4o_mini"]
    
    print_section("GPT-4o-mini FRONTIER: 45 Cells Summary")
    print(f"Total runs found: {len(frontier)}")
    
    # Group by scene
    by_scene = defaultdict(list)
    for r in frontier:
        by_scene[r["scene"]].append(r)
    
    for scene_name in ["level_control", "sorting_weight", "sorting_height_basic"]:
        scene_runs = by_scene.get(scene_name, [])
        print(f"\n--- {scene_name} ({len(scene_runs)} runs) ---")
        
        if not scene_runs:
            print("  No runs found!")
            continue
        
        # Group by condition
        by_cond = defaultdict(list)
        for r in scene_runs:
            key = (r["context"], r["defense"])
            by_cond[key].append(r)
        
        print(f"  {'Context':<10} {'Defense':<15} {'N':>3} {'Proposals':>10} {'Valid':>6} {'Success':>8} {'ASR%':>6} {'VAR%':>6} {'ShBlk':>6} {'LLMBlk':>7}")
        print(f"  {'-'*10} {'-'*15} {'-'*3} {'-'*10} {'-'*6} {'-'*8} {'-'*6} {'-'*6} {'-'*6} {'-'*7}")
        
        for ctx in ["minimal", "partial", "full"]:
            for defense in ["none", "llm_defender", "llm_combined"]:
                key = (ctx, defense)
                cell_runs = by_cond.get(key, [])
                if not cell_runs:
                    continue
                
                n = len(cell_runs)
                avg_prop = sum(r["n_proposals"] for r in cell_runs) / n
                avg_valid = sum(r["n_valid"] for r in cell_runs) / n
                avg_success = sum(r["n_success"] for r in cell_runs) / n
                asr = (avg_success / ATTACK_BUDGET) * 100
                var = (avg_valid / avg_prop * 100) if avg_prop > 0 else 0
                avg_sh = sum(r["n_shield_blocked"] for r in cell_runs) / n
                avg_llm = sum(r["n_llm_blocked"] for r in cell_runs) / n
                
                print(f"  {ctx:<10} {defense:<15} {n:>3} {avg_prop:>10.1f} {avg_valid:>6.1f} {avg_success:>8.1f} {asr:>6.1f} {var:>6.1f} {avg_sh:>6.1f} {avg_llm:>7.1f}")
        
        # Target analysis
        all_targets = defaultdict(int)
        for r in scene_runs:
            for tag, count in r["targets"].items():
                all_targets[tag] += count
        
        print(f"\n  Top attack targets:")
        for tag, count in sorted(all_targets.items(), key=lambda x: -x[1])[:5]:
            print(f"    {tag}: {count} proposals")


def analyze_qwen_baseline(runs):
    """Analyze Qwen2.5-3B baseline for comparison."""
    # Qwen runs: model_variant is either "qwen25_3b" or just default (not gpt4o_mini)
    qwen = [r for r in runs if r["model"] != "gpt4o_mini" and r["model"] != "unknown"]
    # Also include runs where model_variant might be empty/default
    default_runs = [r for r in runs if r["model"] in ("qwen25_3b", "base", "")]
    qwen.extend(default_runs)
    # Deduplicate
    seen = set()
    qwen_dedup = []
    for r in qwen:
        if r["run_id"] not in seen:
            seen.add(r["run_id"])
            qwen_dedup.append(r)
    qwen = qwen_dedup
    
    if not qwen:
        print_section("Qwen2.5-3B Baseline: No runs found with explicit model_variant")
        print("  (Qwen runs may not have model_variant set in metadata)")
        return {}
    
    print_section(f"Qwen2.5-3B Baseline: {len(qwen)} runs")
    
    by_scene = defaultdict(list)
    for r in qwen:
        by_scene[r["scene"]].append(r)
    
    qwen_summary = {}
    
    for scene_name in ["level_control", "sorting_weight", "sorting_height_basic"]:
        scene_runs = by_scene.get(scene_name, [])
        if not scene_runs:
            continue
        
        print(f"\n--- {scene_name} ({len(scene_runs)} runs) ---")
        
        by_cond = defaultdict(list)
        for r in scene_runs:
            key = (r["context"], r["defense"])
            by_cond[key].append(r)
        
        print(f"  {'Context':<10} {'Defense':<15} {'N':>3} {'Proposals':>10} {'Valid':>6} {'Success':>8} {'ASR%':>6}")
        print(f"  {'-'*10} {'-'*15} {'-'*3} {'-'*10} {'-'*6} {'-'*8} {'-'*6}")
        
        for ctx in ["minimal", "partial", "full"]:
            for defense in ["none", "llm_defender", "llm_combined"]:
                key = (ctx, defense)
                cell_runs = by_cond.get(key, [])
                if not cell_runs:
                    continue
                
                n = len(cell_runs)
                avg_prop = sum(r["n_proposals"] for r in cell_runs) / n
                avg_valid = sum(r["n_valid"] for r in cell_runs) / n
                avg_success = sum(r["n_success"] for r in cell_runs) / n
                asr = (avg_success / ATTACK_BUDGET) * 100
                
                print(f"  {ctx:<10} {defense:<15} {n:>3} {avg_prop:>10.1f} {avg_valid:>6.1f} {avg_success:>8.1f} {asr:>6.1f}")
                
                qwen_summary[(scene_name, ctx, defense)] = {
                    "avg_proposals": avg_prop,
                    "avg_valid": avg_valid,
                    "avg_success": avg_success,
                    "asr": asr,
                }
    
    return qwen_summary


def compare_models(runs):
    """Side-by-side comparison of GPT-4o-mini vs Qwen2.5-3B."""
    frontier = [r for r in runs if r["model"] == "gpt4o_mini"]
    qwen = [r for r in runs if r["model"] != "gpt4o_mini"]
    
    print_section("HEAD-TO-HEAD: GPT-4o-mini vs Qwen2.5-3B")
    
    for scene_name in ["level_control", "sorting_weight", "sorting_height_basic"]:
        f_scene = [r for r in frontier if r["scene"] == scene_name]
        q_scene = [r for r in qwen if r["scene"] == scene_name]
        
        if not f_scene:
            continue
        
        print(f"\n--- {scene_name} ---")
        print(f"  {'Condition':<25} | {'GPT-4o-mini':^30} | {'Qwen2.5-3B':^30}")
        print(f"  {'':<25} | {'Prop':>5} {'VAR%':>6} {'ASR%':>6} {'Lat':>7}ms | {'Prop':>5} {'VAR%':>6} {'ASR%':>6} {'Lat':>7}ms")
        print(f"  {'-'*25}-+-{'-'*30}-+-{'-'*30}")
        
        for ctx in ["minimal", "partial", "full"]:
            for defense in ["none", "llm_defender", "llm_combined"]:
                f_cell = [r for r in f_scene if r["context"] == ctx and r["defense"] == defense]
                q_cell = [r for r in q_scene if r["context"] == ctx and r["defense"] == defense]
                
                if not f_cell:
                    continue
                
                cond = f"{ctx}/{defense}"
                
                # GPT-4o-mini stats
                fn = len(f_cell)
                f_prop = sum(r["n_proposals"] for r in f_cell) / fn
                f_valid = sum(r["n_valid"] for r in f_cell) / fn
                f_success = sum(r["n_success"] for r in f_cell) / fn
                f_asr = (f_success / ATTACK_BUDGET) * 100
                f_var = (f_valid / f_prop * 100) if f_prop > 0 else 0
                f_lat = sum(r["avg_latency_ms"] for r in f_cell) / fn
                
                # Qwen stats
                if q_cell:
                    qn = len(q_cell)
                    q_prop = sum(r["n_proposals"] for r in q_cell) / qn
                    q_valid = sum(r["n_valid"] for r in q_cell) / qn
                    q_success = sum(r["n_success"] for r in q_cell) / qn
                    q_asr = (q_success / ATTACK_BUDGET) * 100
                    q_var = (q_valid / q_prop * 100) if q_prop > 0 else 0
                    q_lat = sum(r["avg_latency_ms"] for r in q_cell) / qn
                    q_str = f"{q_prop:>5.1f} {q_var:>6.1f} {q_asr:>6.1f} {q_lat:>7.0f}"
                else:
                    q_str = f"{'N/A':>5} {'N/A':>6} {'N/A':>6} {'N/A':>7}"
                
                f_str = f"{f_prop:>5.1f} {f_var:>6.1f} {f_asr:>6.1f} {f_lat:>7.0f}"
                print(f"  {cond:<25} | {f_str} | {q_str}")


def key_findings(runs):
    """Extract key findings for paper."""
    frontier = [r for r in runs if r["model"] == "gpt4o_mini"]
    
    print_section("KEY FINDINGS FOR PAPER")
    
    # 1. Self-deterrence comparison
    print("\n1. SELF-DETERRENCE (GPT-4o-mini vs Qwen2.5-3B)")
    for scene in ["level_control", "sorting_weight", "sorting_height_basic"]:
        f_none = [r for r in frontier if r["scene"] == scene and r["defense"] == "none"]
        if f_none:
            avg_prop = sum(r["n_proposals"] for r in f_none) / len(f_none)
            print(f"   {scene}: GPT-4o-mini avg {avg_prop:.1f}/10 proposals (no self-deterrence)")
    
    # 2. Attack effectiveness across scenes
    print("\n2. ATTACK EFFECTIVENESS (ASR) — no defense cells")
    for scene in ["level_control", "sorting_weight", "sorting_height_basic"]:
        f_none = [r for r in frontier if r["scene"] == scene and r["defense"] == "none"]
        if f_none:
            avg_success = sum(r["n_success"] for r in f_none) / len(f_none)
            avg_valid = sum(r["n_valid"] for r in f_none) / len(f_none)
            asr = (avg_success / ATTACK_BUDGET) * 100
            print(f"   {scene}: ASR={asr:.1f}%, avg_valid={avg_valid:.1f}, avg_success={avg_success:.1f}")
    
    # 3. LLM defender effectiveness
    print("\n3. LLM DEFENDER EFFECTIVENESS")
    for scene in ["level_control", "sorting_weight", "sorting_height_basic"]:
        f_def = [r for r in frontier if r["scene"] == scene and r["defense"] == "llm_defender"]
        if f_def:
            avg_llm_blk = sum(r["n_llm_blocked"] for r in f_def) / len(f_def)
            avg_prop = sum(r["n_proposals"] for r in f_def) / len(f_def)
            block_rate = (avg_llm_blk / avg_prop * 100) if avg_prop > 0 else 0
            print(f"   {scene}: LLM defender blocks {avg_llm_blk:.1f}/{avg_prop:.1f} proposals ({block_rate:.0f}%)")
    
    # 4. Latency comparison
    print("\n4. LATENCY")
    for scene in ["level_control", "sorting_weight", "sorting_height_basic"]:
        f_all = [r for r in frontier if r["scene"] == scene]
        if f_all:
            avg_lat = sum(r["avg_latency_ms"] for r in f_all) / len(f_all)
            print(f"   {scene}: avg LLM latency = {avg_lat:.0f}ms")
    
    # 5. Dominant target tags per scene
    print("\n5. DOMINANT ATTACK TARGETS")
    for scene in ["level_control", "sorting_weight", "sorting_height_basic"]:
        f_scene = [r for r in frontier if r["scene"] == scene]
        all_targets = defaultdict(int)
        for r in f_scene:
            for tag, count in r["targets"].items():
                all_targets[tag] += count
        
        if all_targets:
            top = sorted(all_targets.items(), key=lambda x: -x[1])[:3]
            tags_str = ", ".join(f"{t}({c})" for t, c in top)
            print(f"   {scene}: {tags_str}")


def main():
    print("Loading all experiment runs from", DATA_DIR)
    runs = load_runs()
    print(f"Loaded {len(runs)} total runs")
    
    # Count by model
    models = defaultdict(int)
    for r in runs:
        models[r["model"]] += 1
    print(f"By model: {dict(models)}")
    
    analyze_frontier(runs)
    analyze_qwen_baseline(runs)
    compare_models(runs)
    key_findings(runs)
    
    print(f"\n{'='*70}")
    print("  ANALYSIS COMPLETE")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
