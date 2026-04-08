#!/usr/bin/env python3
"""
Generate paper-ready LaTeX tables (Tables 3--6) from v2 experiment data.

Usage:
    python -m cpsforge.analysis.generate_tables

Reads:  data/raw/v2_*/*/unified_steps.parquet
        data/checkpoint.json  (for RQ cell-id validation)
Writes: overleaf/sections/table3_context.tex
        overleaf/sections/table4_attacker.tex
        overleaf/sections/table5_defense.tex
        overleaf/sections/table6_crossmodel.tex

Post-hoc ASR: For each write_executed=True step N, we compare
observation_dict at step N-1 (before) and N+2 (after). If the target tag
moved toward the written value, the attack is counted as successful.

RQ-specific filtering: Each table limits to exactly 3 runs per
configuration cell (matching the 3-repeat experiment design) to avoid
cross-RQ run inflation.
"""

from __future__ import annotations

import glob
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_GLOB = str(PROJECT_ROOT / "data" / "raw" / "v2_*" / "*" / "unified_steps.parquet")
CHECKPOINT_PATH = PROJECT_ROOT / "data" / "checkpoint.json"
OVERLEAF_DIR = PROJECT_ROOT / "overleaf" / "sections"

RUNS_PER_CELL = 3  # Experiment design: 3 repeats per configuration

SCENE_LABELS = {
    "level_control": "Level Control",
    "sorting_weight": "Sort.~Weight",
    "sorting_height_basic": "Sort.~Height",
}

SCENE_ORDER = ["level_control", "sorting_weight", "sorting_height_basic"]

CONTEXT_ORDER = ["minimal", "partial", "full"]
CONTEXT_LABELS = {"minimal": "Minimal", "partial": "Partial", "full": "Full"}

ATTACKER_ORDER = ["random", "static_llm", "online_mitm"]
ATTACKER_LABELS = {
    "random": "Random",
    "static_llm": "Static LLM",
    "online_mitm": "Online MITM",
}

DEFENSE_ORDER = [
    "none", "baseline", "phase_aware", "intent",
    "combined", "llm_defender", "llm_combined",
]
DEFENSE_LABELS = {
    "none": "None",
    "baseline": "Baseline",
    "phase_aware": "Phase-Aware",
    "intent": "Intent",
    "combined": "Combined",
    "llm_defender": "LLM Defender",
    "llm_combined": "LLM+Combined",
}

MODEL_ORDER = ["qwen25_3b", "qwen3_17b", "smollm3_3b"]
MODEL_LABELS = {
    "qwen25_3b": "Qwen2.5-3B",
    "qwen3_17b": "Qwen3-1.7B",
    "smollm3_3b": "SmolLM3-3B",
}

TABLE_FOOTNOTE = (
    r"\vspace{2pt}"
    "\n"
    r"\noindent\footnotesize{3 repeats per configuration; ASR computed post-hoc.}"
)


# ---------------------------------------------------------------------------
# Checkpoint loading (for validation / logging)
# ---------------------------------------------------------------------------

def load_checkpoint_cells(rq_prefix: str) -> List[str]:
    """Load cell_ids from checkpoint.json that match a given RQ prefix."""
    if not CHECKPOINT_PATH.exists():
        print(f"  Warning: {CHECKPOINT_PATH} not found, skipping checkpoint validation")
        return []
    with CHECKPOINT_PATH.open() as fh:
        data = json.load(fh)
    completed = data.get("completed", [])
    return [c for c in completed if c.startswith(rq_prefix)]


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_all_data() -> pd.DataFrame:
    """Load and concatenate all v2 experiment parquet files."""
    files = glob.glob(DATA_GLOB)
    if not files:
        raise FileNotFoundError(f"No parquet files found at {DATA_GLOB}")
    dfs = [pd.read_parquet(f) for f in files]
    df = pd.concat(dfs, ignore_index=True)
    # Exclude finetuned runs (no real LLM) -- keep finetune_status=='finetuned'
    # only for RQ4 which explicitly tests finetuned models
    print(f"Loaded {len(df)} rows from {len(files)} parquet files "
          f"({df['run_id'].nunique()} runs)")
    return df


# ---------------------------------------------------------------------------
# Post-hoc ASR computation
# ---------------------------------------------------------------------------

def compute_posthoc_success(run_df: pd.DataFrame) -> pd.Series:
    """For a single run (sorted by step_id), compute post-hoc attack success.

    Returns a boolean Series aligned to run_df index, True where write
    succeeded (tag moved toward written value).
    """
    run_df = run_df.sort_values("step_id").reset_index(drop=True)
    success = pd.Series(False, index=run_df.index)

    write_mask = run_df["write_executed"] == True
    for idx in run_df[write_mask].index:
        step = run_df.loc[idx, "step_id"]
        tag = run_df.loc[idx, "action_target_tag"]
        val = run_df.loc[idx, "action_value"]

        if pd.isna(tag) or pd.isna(val):
            continue

        # Find before (step N-1) and after (step N+2) rows
        before = run_df[run_df["step_id"] == step - 1]
        after = run_df[run_df["step_id"] == step + 2]
        if before.empty or after.empty:
            continue

        b_obs = before.iloc[0]["observation_dict"]
        a_obs = after.iloc[0]["observation_dict"]
        if not isinstance(b_obs, dict) or not isinstance(a_obs, dict):
            continue
        if tag not in b_obs or tag not in a_obs:
            continue

        b_val = b_obs[tag]
        a_val = a_obs[tag]

        # Boolean tags
        if isinstance(val, bool) or isinstance(b_val, bool):
            if a_val == val and b_val != val:
                success[idx] = True
        else:
            try:
                dist_before = abs(float(b_val) - float(val))
                dist_after = abs(float(a_val) - float(val))
                if dist_after < dist_before:
                    success[idx] = True
            except (ValueError, TypeError):
                pass

    return success


def add_posthoc_asr(df: pd.DataFrame) -> pd.DataFrame:
    """Add 'posthoc_success' column to the full dataframe."""
    results = []
    for run_id, run_df in df.groupby("run_id"):
        s = compute_posthoc_success(run_df)
        s.index = run_df.index
        results.append(s)
    df = df.copy()
    df["posthoc_success"] = pd.concat(results).reindex(df.index, fill_value=False)
    total_writes = (df["write_executed"] == True).sum()
    total_succ = df["posthoc_success"].sum()
    print(f"Post-hoc ASR: {total_succ}/{total_writes} writes successful "
          f"({100*total_succ/max(total_writes,1):.1f}%)")
    return df


# ---------------------------------------------------------------------------
# RQ-specific run limiting
# ---------------------------------------------------------------------------

def _limit_runs_per_group(
    df: pd.DataFrame,
    group_cols: List[str],
    max_runs: int = RUNS_PER_CELL,
    latest: bool = False,
) -> pd.DataFrame:
    """Limit to at most *max_runs* unique run_ids per configuration group.

    Within each group defined by *group_cols*, sorts run_ids
    chronologically (lexicographic on timestamp-based run_id) and keeps
    only the first *max_runs* (or last if latest=True).
    """
    if df.empty:
        return df

    # Get unique run_ids per group, sorted
    keep_run_ids = set()
    for _key, grp in df.groupby(group_cols):
        run_ids = sorted(grp["run_id"].unique())
        selected = run_ids[-max_runs:] if latest else run_ids[:max_runs]
        keep_run_ids.update(selected)

    filtered = df[df["run_id"].isin(keep_run_ids)]
    n_before = df["run_id"].nunique()
    n_after = filtered["run_id"].nunique()
    if n_before != n_after:
        print(f"  RQ filter: {n_before} -> {n_after} runs "
              f"(limited to {max_runs} per {group_cols})")
    return filtered


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def _asr_pct(successes: int, writes: int) -> str:
    """Format ASR as percentage string."""
    if writes == 0:
        return "0.0"
    return f"{100 * successes / writes:.1f}"


def _safe_mean(series: pd.Series) -> float:
    vals = series.dropna()
    return float(vals.mean()) if len(vals) > 0 else 0.0


# ---------------------------------------------------------------------------
# Table 3: RQ1 Context Ablation
# ---------------------------------------------------------------------------

def generate_table3(df: pd.DataFrame) -> str:
    """RQ1 Context Ablation: online_mitm, defense=none, base model.

    RQ1 has 27 cells: 3 contexts x 3 scenes x 3 repeats.
    We limit to exactly 3 runs per (scene, context_level) group.
    """
    # Log checkpoint validation
    rq1_cells = load_checkpoint_cells("RQ1_")
    print(f"  RQ1 checkpoint cells: {len(rq1_cells)} (expected 27)")

    # Base filter: online_mitm, no defense, base model
    sub = df[
        (df["attacker_type"] == "online_mitm") &
        (df["defense_variant"] == "none") &
        (df["finetune_status"] == "base") &
        (df["model_variant"] == "base")
    ]

    # Limit to 3 runs per (scene, context_level) cell
    sub = _limit_runs_per_group(sub, ["scene", "context_level"])

    rows = []
    for scene in SCENE_ORDER:
        for ctx in CONTEXT_ORDER:
            cell = sub[(sub["scene"] == scene) & (sub["context_level"] == ctx)]
            if cell.empty:
                continue
            n_runs = cell["run_id"].nunique()
            proposals = (cell["parsed_decision"] == "attack").sum()
            writes = (cell["write_executed"] == True).sum()
            successes = cell["posthoc_success"].sum()
            asr = _asr_pct(successes, writes)
            latency = _safe_mean(cell["llm_latency_ms"])
            rows.append((scene, ctx, n_runs, proposals, writes,
                         int(successes), asr, latency))

    # Build LaTeX
    lines = []
    lines.append(r"% Table 3 --- RQ1 Context Ablation")
    lines.append(r"% Generated by: python -m cpsforge.analysis.generate_tables")
    lines.append(r"% RQ-specific filtering: limited to 3 runs per (scene, context) cell")
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{RQ1: Context ablation for online MITM attacker (base Qwen2.5-3B, no defense).}")
    lines.append(r"\label{tab:context_ablation}")
    lines.append(r"\small")
    lines.append(r"\setlength{\tabcolsep}{3pt}")
    lines.append(r"\begin{tabular}{llrrrrrr}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Scene} & \textbf{Context} & \textbf{Runs} & \textbf{Prop.} & \textbf{Writes} & \textbf{Succ.} & \textbf{ASR\%} & \textbf{Lat.(ms)} \\")
    lines.append(r"\midrule")

    prev_scene = None
    for (scene, ctx, runs, props, writes, succ, asr, lat) in rows:
        scene_label = SCENE_LABELS.get(scene, scene)
        ctx_label = CONTEXT_LABELS.get(ctx, ctx)
        if prev_scene is not None and scene != prev_scene:
            lines.append(r"\midrule")
        scene_col = scene_label if scene != prev_scene else ""
        lines.append(
            f"{scene_col} & {ctx_label} & {runs} & {props} & {writes} & "
            f"{succ} & {asr} & {lat:.0f} \\\\"
        )
        prev_scene = scene

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(TABLE_FOOTNOTE)
    lines.append(r"\end{table}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Table 4: RQ3 Attacker Comparison
# ---------------------------------------------------------------------------

def generate_table4(df: pd.DataFrame) -> str:
    """RQ3 Attacker Comparison: defense=none, base model.

    RQ3 has 27 cells: 3 attackers x 3 scenes x 3 repeats.
    We limit to exactly 3 runs per (scene, attacker_type) group.
    """
    rq3_cells = load_checkpoint_cells("RQ3_")
    print(f"  RQ3 checkpoint cells: {len(rq3_cells)} (expected 27)")

    sub = df[
        (df["defense_variant"] == "none") &
        (df["finetune_status"] == "base") &
        (df["model_variant"] == "base")
    ]

    # Limit to 3 runs per (scene, attacker_type) cell
    sub = _limit_runs_per_group(sub, ["scene", "attacker_type"])

    rows = []
    for scene in SCENE_ORDER:
        for atype in ATTACKER_ORDER:
            cell = sub[(sub["scene"] == scene) & (sub["attacker_type"] == atype)]
            if cell.empty:
                continue
            n_runs = cell["run_id"].nunique()
            proposals = (cell["parsed_decision"] == "attack").sum()
            writes = (cell["write_executed"] == True).sum()
            successes = cell["posthoc_success"].sum()
            asr = _asr_pct(successes, writes)
            rows.append((scene, atype, n_runs, proposals, writes,
                         int(successes), asr))

    lines = []
    lines.append(r"% Table 4 --- RQ3 Attacker Comparison")
    lines.append(r"% Generated by: python -m cpsforge.analysis.generate_tables")
    lines.append(r"% RQ-specific filtering: limited to 3 runs per (scene, attacker) cell")
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{RQ3: Attacker comparison (base Qwen2.5-3B, no defense). Random = bounded random perturbations; Static LLM = one-shot batch; Online MITM = core contribution.}")
    lines.append(r"\label{tab:attacker_comparison}")
    lines.append(r"\small")
    lines.append(r"\setlength{\tabcolsep}{3pt}")
    lines.append(r"\begin{tabular}{llrrrrr}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Scene} & \textbf{Attacker} & \textbf{Runs} & \textbf{Prop.} & \textbf{Writes} & \textbf{Succ.} & \textbf{ASR\%} \\")
    lines.append(r"\midrule")

    prev_scene = None
    for (scene, atype, runs, props, writes, succ, asr) in rows:
        scene_label = SCENE_LABELS.get(scene, scene)
        atype_label = ATTACKER_LABELS.get(atype, atype)
        if prev_scene is not None and scene != prev_scene:
            lines.append(r"\midrule")
        scene_col = scene_label if scene != prev_scene else ""
        lines.append(
            f"{scene_col} & {atype_label} & {runs} & {props} & {writes} & "
            f"{succ} & {asr} \\\\"
        )
        prev_scene = scene

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(TABLE_FOOTNOTE)
    lines.append(r"\end{table}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Table 5: RQ4 Defense Comparison
# ---------------------------------------------------------------------------

def generate_table5(df: pd.DataFrame) -> str:
    """RQ4 Defense Comparison: online_mitm, base model.

    RQ4 has 126 cells: 2 models x 7 defenses x 3 scenes x 3 repeats.
    For the base-model table, limit to 3 runs per (scene, defense_variant).
    """
    rq4_cells = load_checkpoint_cells("RQ4_")
    print(f"  RQ4 checkpoint cells: {len(rq4_cells)} (expected 126)")

    sub = df[
        (df["attacker_type"] == "online_mitm") &
        (df["finetune_status"] == "base") &
        (df["model_variant"] == "base")
    ]

    # Limit to 3 runs per (scene, defense_variant) cell
    sub = _limit_runs_per_group(sub, ["scene", "defense_variant"])

    rows = []
    for scene in SCENE_ORDER:
        for dv in DEFENSE_ORDER:
            cell = sub[(sub["scene"] == scene) & (sub["defense_variant"] == dv)]
            if cell.empty:
                continue
            n_runs = cell["run_id"].nunique()
            proposals = (cell["parsed_decision"] == "attack").sum()

            # Per-mechanism blocked counts (informational, may overlap)
            phase_blocked = int(cell["phase_shield_blocked"].sum()) if "phase_shield_blocked" in cell else 0
            intent_blocked = int(cell["intent_check_blocked"].sum()) if "intent_check_blocked" in cell else 0
            llm_blocked = 0
            if "llm_defender_blocked" in cell.columns:
                llm_blocked = int(cell["llm_defender_blocked"].fillna(False).astype(bool).sum())

            writes = (cell["write_executed"] == True).sum()
            successes = cell["posthoc_success"].sum()
            # Total blocked = proposals that did NOT become writes
            # (avoids double-counting across defense stages)
            total_blocked = int(proposals - writes)
            asr = _asr_pct(successes, writes)
            prevention = _asr_pct(total_blocked, proposals) if proposals > 0 else "0.0"

            rows.append((scene, dv, n_runs, proposals, int(total_blocked),
                         writes, int(successes), asr, prevention,
                         phase_blocked, intent_blocked, llm_blocked))

    lines = []
    lines.append(r"% Table 5 --- RQ4 Defense Comparison")
    lines.append(r"% Generated by: python -m cpsforge.analysis.generate_tables")
    lines.append(r"% RQ-specific filtering: limited to 3 runs per (scene, defense) cell")
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{RQ4: Defense comparison for online MITM attacker (base Qwen2.5-3B). Prevention rate = fraction of attack proposals blocked before PLC write. ``None'' = no RQ4 defense; the mandatory safety shield (always active) accounts for any nonzero Blk.\ in ``None'' rows.}")
    lines.append(r"\label{tab:defense_comparison}")
    lines.append(r"\small")
    lines.append(r"\setlength{\tabcolsep}{2pt}")
    lines.append(r"\resizebox{\columnwidth}{!}{%")
    lines.append(r"\begin{tabular}{llrrrrrrrrrr}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Scene} & \textbf{Defense} & \textbf{Runs} & \textbf{Prop.} & \textbf{Blk.} & \textbf{Wr.} & \textbf{Succ.} & \textbf{ASR\%} & \textbf{Prev.\%} & \textbf{Ph.} & \textbf{Int.} & \textbf{LLM} \\")
    lines.append(r"\midrule")

    prev_scene = None
    for (scene, dv, runs, props, blocked, writes, succ, asr, prev,
         ph, intent, llm) in rows:
        scene_label = SCENE_LABELS.get(scene, scene)
        dv_label = DEFENSE_LABELS.get(dv, dv)
        if prev_scene is not None and scene != prev_scene:
            lines.append(r"\midrule")
        scene_col = scene_label if scene != prev_scene else ""
        lines.append(
            f"{scene_col} & {dv_label} & {runs} & {props} & {blocked} & "
            f"{writes} & {succ} & {asr} & {prev} & "
            f"{ph} & {intent} & {llm} \\\\"
        )
        prev_scene = scene

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}%")
    lines.append(r"}")
    lines.append(TABLE_FOOTNOTE)
    lines.append(r"\end{table}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Table 6: RQ5 Cross-Model
# ---------------------------------------------------------------------------

def generate_table6(df: pd.DataFrame) -> str:
    """RQ5 Cross-Model: defense=none, cross-model variants.

    RQ5 has 72 cells: 3 models x 2 contexts x 2 attackers x 2 scenes x 3 repeats.
    We limit to 3 runs per (model_variant, scene) group for this summary table.
    """
    rq5_cells = load_checkpoint_cells("RQ5_")
    print(f"  RQ5 checkpoint cells: {len(rq5_cells)} (expected 72)")

    sub = df[
        (df["defense_variant"] == "none") &
        (df["model_variant"].isin(MODEL_ORDER))
    ]

    # Limit to 3 runs per full RQ5 cell (model x scene x context x attacker)
    # then aggregate by (model, scene) in the table
    sub = _limit_runs_per_group(sub, ["model_variant", "scene", "context_level", "attacker_type"])

    rows = []
    for model in MODEL_ORDER:
        for scene in SCENE_ORDER:
            cell = sub[(sub["model_variant"] == model) & (sub["scene"] == scene)]
            if cell.empty:
                continue
            n_runs = cell["run_id"].nunique()
            proposals = (cell["parsed_decision"] == "attack").sum()
            writes = (cell["write_executed"] == True).sum()
            successes = cell["posthoc_success"].sum()
            asr = _asr_pct(successes, writes)
            rows.append((model, scene, n_runs, proposals, writes,
                         int(successes), asr))

    lines = []
    lines.append(r"% Table 6 --- RQ5 Cross-Model Comparison")
    lines.append(r"% Generated by: python -m cpsforge.analysis.generate_tables")
    lines.append(r"% RQ-specific filtering: limited to 3 runs per (model, scene) cell")
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{RQ5: Cross-model comparison (no defense). Runs column aggregates across context levels (minimal, full) and attacker types (static LLM, online MITM) for each model--scene pair; ASR is computed over all executed writes within this aggregate. All models run in 4-bit NF4 quantization.}")
    lines.append(r"\label{tab:crossmodel}")
    lines.append(r"\small")
    lines.append(r"\setlength{\tabcolsep}{3pt}")
    lines.append(r"\begin{tabular}{llrrrrr}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Model} & \textbf{Scene} & \textbf{Runs} & \textbf{Prop.} & \textbf{Writes} & \textbf{Succ.} & \textbf{ASR\%} \\")
    lines.append(r"\midrule")

    prev_model = None
    for (model, scene, runs, props, writes, succ, asr) in rows:
        model_label = MODEL_LABELS.get(model, model)
        scene_label = SCENE_LABELS.get(scene, scene)
        if prev_model is not None and model != prev_model:
            lines.append(r"\midrule")
        model_col = model_label if model != prev_model else ""
        lines.append(
            f"{model_col} & {scene_label} & {runs} & {props} & {writes} & "
            f"{succ} & {asr} \\\\"
        )
        prev_model = model

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(TABLE_FOOTNOTE)
    lines.append(r"\end{table}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Table RQ2: Fine-Tuning Comparison
# ---------------------------------------------------------------------------

def generate_table_rq2(df: pd.DataFrame) -> str:
    """RQ2: Before/after fine-tuning (base vs. finetuned Qwen2.5-3B).

    36 cells: 2 models x 2 contexts x 3 scenes x 3 repeats.
    attacker=online_mitm, defense=none.
    """
    rq2_cells = load_checkpoint_cells("RQ2_")
    print(f"  RQ2 checkpoint cells: {len(rq2_cells)} (expected 36)")

    sub = df[
        (df["attacker_type"] == "online_mitm") &
        (df["defense_variant"] == "none") &
        (df["finetune_status"].isin(["base", "finetuned"]))
    ]
    sub = _limit_runs_per_group(sub, ["scene", "finetune_status", "context_level"])

    rows = []
    for scene in SCENE_ORDER:
        for ctx in ["minimal", "full"]:
            for ft in ["base", "finetuned"]:
                cell = sub[
                    (sub["scene"] == scene) &
                    (sub["context_level"] == ctx) &
                    (sub["finetune_status"] == ft)
                ]
                if cell.empty:
                    continue
                n_runs = cell["run_id"].nunique()
                # LLM calls = steps where should_call_llm() fired (proxied by non-null llm_raw_output)
                llm_calls = int(cell["llm_raw_output"].notna().sum()) if "llm_raw_output" in cell.columns else 0
                proposals = int((cell["parsed_decision"] == "attack").sum())
                # VAR = schema-valid outputs / total LLM calls
                valid = int(cell["parse_success"].fillna(False).sum()) if "parse_success" in cell.columns else 0
                var = _asr_pct(valid, llm_calls) if llm_calls > 0 else "N/A"
                writes = int((cell["write_executed"] == True).sum())
                successes = int(cell["posthoc_success"].sum())
                asr = _asr_pct(successes, writes)
                rows.append((scene, ctx, ft, n_runs, llm_calls, var, proposals, writes, successes, asr))

    lines = []
    lines.append(r"% Table RQ2 --- Fine-Tuning Comparison")
    lines.append(r"% Generated by: python -m cpsforge.analysis.generate_tables")
    lines.append(r"% RQ-specific filtering: limited to 3 runs per (scene, context, model) cell")
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{RQ2: Fine-tuning effect on attack capability (online MITM, no defense). Base = Qwen2.5-3B-Instruct; FT = same model with QLoRA v2 adapter. VAR = schema-valid outputs / LLM calls.}")
    lines.append(r"\label{tab:finetune_comparison}")
    lines.append(r"\small")
    lines.append(r"\setlength{\tabcolsep}{3pt}")
    lines.append(r"\resizebox{\columnwidth}{!}{%")
    lines.append(r"\begin{tabular}{lllrrrrrrr}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Scene} & \textbf{Ctx} & \textbf{Model} & \textbf{Runs} & \textbf{LLM calls} & \textbf{VAR\%} & \textbf{Prop.} & \textbf{Writes} & \textbf{Succ.} & \textbf{ASR\%} \\")
    lines.append(r"\midrule")

    prev_scene = None
    for (scene, ctx, ft, runs, llm_calls, var, props, writes, succ, asr) in rows:
        scene_label = SCENE_LABELS.get(scene, scene)
        ctx_label = CONTEXT_LABELS.get(ctx, ctx)
        ft_label = "Base" if ft == "base" else "FT"
        if prev_scene is not None and scene != prev_scene:
            lines.append(r"\midrule")
        scene_col = scene_label if scene != prev_scene else ""
        lines.append(
            f"{scene_col} & {ctx_label} & {ft_label} & {runs} & {llm_calls} & {var} & {props} & {writes} & {succ} & {asr} \\\\"
        )
        prev_scene = scene

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}%")
    lines.append(r"}")
    lines.append(TABLE_FOOTNOTE)
    lines.append(r"\end{table}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Table RQ4 Finetuned: Defense Comparison (finetuned model)
# ---------------------------------------------------------------------------

def generate_table_rq4_finetuned(df: pd.DataFrame) -> str:
    """RQ4 Defense Comparison with finetuned attacker/defender.

    63 cells: finetuned model x 7 defenses x 3 scenes x 3 repeats.
    """
    sub = df[
        (df["attacker_type"] == "online_mitm") &
        (df["finetune_status"] == "finetuned")
    ]
    # Use latest=True: RQ4 finetuned runs are most recent; earlier runs are RQ2
    sub = _limit_runs_per_group(sub, ["scene", "defense_variant"], latest=True)

    rows = []
    for scene in SCENE_ORDER:
        for dv in DEFENSE_ORDER:
            cell = sub[(sub["scene"] == scene) & (sub["defense_variant"] == dv)]
            if cell.empty:
                continue
            n_runs = cell["run_id"].nunique()
            proposals = int((cell["parsed_decision"] == "attack").sum())
            writes = int((cell["write_executed"] == True).sum())
            successes = int(cell["posthoc_success"].sum())
            llm_blocked = 0
            if "llm_defender_blocked" in cell.columns:
                llm_blocked = int(cell["llm_defender_blocked"].fillna(False).astype(bool).sum())
            total_blocked = int(proposals - writes)
            asr = _asr_pct(successes, writes)
            prevention = _asr_pct(total_blocked, proposals) if proposals > 0 else "0.0"
            rows.append((scene, dv, n_runs, proposals, total_blocked, writes, successes, asr, prevention, llm_blocked))

    lines = []
    lines.append(r"% Table RQ4 Finetuned --- Defense Comparison (finetuned attacker)")
    lines.append(r"% Generated by: python -m cpsforge.analysis.generate_tables")
    lines.append(r"% RQ-specific filtering: limited to 3 runs per (scene, defense) cell")
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{RQ4 (finetuned): Defense comparison for finetuned MITM attacker (Qwen2.5-3B+QLoRA, full context). ``None'' = no RQ4 defense; safety shield always active. Sort.~Weight None: 6/13 proposals blocked by safety shield (finetuned model targets \texttt{light\_thresh} with out-of-range values 10.5--15.0). Sort.~Height None: finetuned model self-deterred (0 proposals, full context).}")
    lines.append(r"\label{tab:defense_finetuned}")
    lines.append(r"\small")
    lines.append(r"\setlength{\tabcolsep}{2pt}")
    lines.append(r"\resizebox{\columnwidth}{!}{%")
    lines.append(r"\begin{tabular}{llrrrrrrrrr}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Scene} & \textbf{Defense} & \textbf{Runs} & \textbf{Prop.} & \textbf{Blk.} & \textbf{Wr.} & \textbf{Succ.} & \textbf{ASR\%} & \textbf{Prev.\%} & \textbf{LLM} \\")
    lines.append(r"\midrule")

    prev_scene = None
    for (scene, dv, runs, props, blocked, writes, succ, asr, prev, llm) in rows:
        scene_label = SCENE_LABELS.get(scene, scene)
        dv_label = DEFENSE_LABELS.get(dv, dv)
        if prev_scene is not None and scene != prev_scene:
            lines.append(r"\midrule")
        scene_col = scene_label if scene != prev_scene else ""
        lines.append(
            f"{scene_col} & {dv_label} & {runs} & {props} & {blocked} & "
            f"{writes} & {succ} & {asr} & {prev} & {llm} \\\\"
        )
        prev_scene = scene

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}%")
    lines.append(r"}")
    lines.append(TABLE_FOOTNOTE)
    lines.append(r"\end{table}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    df = load_all_data()
    # Base-only dataframe for tables 3, 4, 6
    df_base = df[df["finetune_status"] != "finetuned"]
    df_base = add_posthoc_asr(df_base)
    # Full dataframe (base + finetuned) for RQ2 and RQ4-finetuned tables
    df_all = add_posthoc_asr(df)

    tables = {
        "table3_context.tex": generate_table3(df_base),
        "table4_attacker.tex": generate_table4(df_base),
        "table5_defense.tex": generate_table5(df_base),
        "table6_crossmodel.tex": generate_table6(df_base),
        "table_rq2_finetune.tex": generate_table_rq2(df_all),
        "table_rq4_finetuned.tex": generate_table_rq4_finetuned(df_all),
    }

    OVERLEAF_DIR.mkdir(parents=True, exist_ok=True)

    for filename, content in tables.items():
        # Print to stdout
        print(f"\n{'='*60}")
        print(f"  {filename}")
        print(f"{'='*60}")
        print(content)

        # Write to file
        outpath = OVERLEAF_DIR / filename
        outpath.write_text(content, encoding="utf-8")
        print(f"\n  -> Written to {outpath}")

    print(f"\nDone. {len(tables)} tables generated.")


if __name__ == "__main__":
    main()
