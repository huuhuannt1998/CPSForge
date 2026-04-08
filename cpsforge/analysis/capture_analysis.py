"""
cpsforge.analysis.capture_analysis
====================================
Analyze PLC event logs (data/captures/*.jsonl) to produce paper evidence tables
and timeline statistics showing how attacks and defenses affect S7 traffic.

Usage
-----
    python -m cpsforge.analysis.capture_analysis
    python -m cpsforge.analysis.capture_analysis --run-id 20260330T...
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_events(captures_dir: str = "data/captures") -> pd.DataFrame:
    """Load all JSONL capture files into a single DataFrame."""
    records = []
    for path in sorted(Path(captures_dir).glob("*_plc_events.jsonl")):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    if not records:
        print(f"No capture files found in {captures_dir}")
        return pd.DataFrame()
    df = pd.DataFrame(records)
    df["elapsed_s"] = df["elapsed_s"].astype(float)
    return df


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------

def traffic_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Per-run summary: polls/sec, writes, blocks, effective ASR at traffic level.
    """
    rows = []
    for run_id, grp in df.groupby("run_id"):
        polls   = grp[grp["event_type"] == "poll_read"]
        writes  = grp[grp["event_type"] == "attack_write"]
        blocked = grp[grp["event_type"] == "blocked_write"]
        duration = grp["elapsed_s"].max() - grp["elapsed_s"].min()
        poll_rate = len(polls) / duration if duration > 0 else 0

        rows.append({
            "run_id": run_id,
            "duration_s": round(duration, 1),
            "total_events": len(grp),
            "poll_reads": len(polls),
            "poll_rate_hz": round(poll_rate, 3),
            "attack_writes": len(writes),
            "blocked_writes": len(blocked),
            "block_rate": round(len(blocked) / (len(writes) + len(blocked)), 3)
                          if (len(writes) + len(blocked)) > 0 else None,
        })
    return pd.DataFrame(rows)


def block_stage_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    """How many blocks came from each defense stage?"""
    blocked = df[df["event_type"] == "blocked_write"]
    if blocked.empty:
        return pd.DataFrame()
    return (
        blocked.groupby(["run_id", "block_stage"])
        .size()
        .reset_index(name="count")
        .pivot(index="run_id", columns="block_stage", values="count")
        .fillna(0)
        .astype(int)
    )


def write_timeline(df: pd.DataFrame, run_id: str) -> pd.DataFrame:
    """
    Timeline of writes and blocks for a single run — useful for a figure.
    Shows elapsed_s, tag, value, event_type (attack_write | blocked_write), block_stage.
    """
    run_df = df[df["run_id"] == run_id]
    events = run_df[run_df["event_type"].isin(["attack_write", "blocked_write"])].copy()
    cols = ["elapsed_s", "step_id", "event_type", "tag_name",
            "written_value", "block_stage", "block_reason", "suspicion_score"]
    return events[[c for c in cols if c in events.columns]].sort_values("elapsed_s")


def poll_interval_stats(df: pd.DataFrame) -> pd.DataFrame:
    """
    Measure actual inter-poll interval per run — shows framework overhead.
    Expected: ~500 ms. Under attack: may be slightly higher due to LLM latency.
    """
    rows = []
    for run_id, grp in df.groupby("run_id"):
        polls = grp[grp["event_type"] == "poll_read"].sort_values("elapsed_s")
        if len(polls) < 2:
            continue
        intervals = polls["elapsed_s"].diff().dropna() * 1000  # ms
        rows.append({
            "run_id": run_id,
            "n_polls": len(polls),
            "mean_interval_ms": round(intervals.mean(), 1),
            "std_interval_ms": round(intervals.std(), 1),
            "max_interval_ms": round(intervals.max(), 1),
        })
    return pd.DataFrame(rows)


def tag_write_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Which tags were targeted most by attacks and blocks?"""
    writes  = df[df["event_type"] == "attack_write"]
    blocked = df[df["event_type"] == "blocked_write"]
    w_counts = writes.groupby("tag_name").size().rename("attack_writes")
    b_counts = blocked.groupby("tag_name").size().rename("blocked_writes")
    return pd.concat([w_counts, b_counts], axis=1).fillna(0).astype(int).sort_values(
        "attack_writes", ascending=False
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Analyze PLC capture logs")
    parser.add_argument("--captures-dir", default="data/captures")
    parser.add_argument("--run-id", default=None, help="Analyze a specific run only")
    parser.add_argument("--output-dir", default="data/captures/analysis")
    args = parser.parse_args()

    df = load_events(args.captures_dir)
    if df.empty:
        return

    if args.run_id:
        df = df[df["run_id"] == args.run_id]
        print(f"Filtered to run: {args.run_id} ({len(df)} events)")

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    print(f"\nLoaded {len(df)} events from {df['run_id'].nunique()} runs")
    print(f"Event types: {df['event_type'].value_counts().to_dict()}\n")

    summary = traffic_summary(df)
    print("=== Traffic Summary (per run) ===")
    print(summary.to_string(index=False))
    summary.to_csv(out / "traffic_summary.csv", index=False)

    print("\n=== Poll Interval Stats ===")
    pi = poll_interval_stats(df)
    print(pi.to_string(index=False))
    pi.to_csv(out / "poll_intervals.csv", index=False)

    print("\n=== Tag Write Distribution ===")
    td = tag_write_distribution(df)
    print(td.to_string())
    td.to_csv(out / "tag_write_distribution.csv")

    stage_df = block_stage_breakdown(df)
    if not stage_df.empty:
        print("\n=== Block Stage Breakdown ===")
        print(stage_df.to_string())
        stage_df.to_csv(out / "block_stage_breakdown.csv")

    print(f"\nAnalysis saved to {out}/")


if __name__ == "__main__":
    main()
