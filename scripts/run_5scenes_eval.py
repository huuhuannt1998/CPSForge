"""
Run live eval experiments on the 5 confirmed-working Factory I/O scenes.

Scenes (Factory I/O scene # → CPSForge name):
  S1  → from_a_to_b
  S3  → filling_tank
  S12 → level_control
  S19 → sorting_height_basic
  S20 → sorting_weight

For each scene, runs scripted + random attackers with threshold + invariant
defenders. Factory I/O must be manually switched between scene groups.

Usage:
    python scripts/run_5scenes_eval.py
"""
import json
import subprocess
import sys
import time
from pathlib import Path

# Ordered by scene complexity (simplest first)
SCENES = [
    ("from_a_to_b",         1,  "From A to B"),
    ("filling_tank",         3,  "Filling Tank"),
    ("level_control",       12,  "Level Control"),
    ("sorting_height_basic", 19, "Sorting Height Basic"),
    ("sorting_weight",       20, "Sorting Weight"),
]

ATTACKERS = ["scripted", "random"]


def probe_plc() -> bool:
    """Quick PLC connectivity check."""
    r = subprocess.run(
        [sys.executable, "-m", "cpsforge", "plc", "probe"],
        capture_output=True, text=True, timeout=30,
    )
    return r.returncode == 0


def run_one(scene: str, attacker: str) -> dict:
    """Run a single experiment and return result dict."""
    config = f"live_{attacker}_{scene}"
    cmd = [
        sys.executable, "-m", "cpsforge", "run", "attack",
        "--scene", scene,
        "--attacker", attacker,
        "--experiment", config,
        "--no-dry-run",
        "--eval-run",
        "--yes",
    ]
    print(f"  [{attacker:8s}] Running: {' '.join(cmd[-8:])}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    # Look for metrics
    raw_dir = Path("data/raw") / config
    if raw_dir.exists():
        run_dirs = sorted(raw_dir.iterdir(), key=lambda p: p.name)
        if run_dirs:
            latest = run_dirs[-1]
            mf = latest / "metrics.json"
            if mf.exists():
                m = json.loads(mf.read_text())
                print(f"           ASR={m['attack_success_rate']:.2f}  "
                      f"Impact={m['process_impact_score']:.3f}  "
                      f"F1={m['detector_f1']:.2f}  "
                      f"Prec={m['detector_precision']:.2f}  "
                      f"Rec={m['detector_recall']:.2f}  "
                      f"Lat={m['detection_latency_ms']:.0f}ms  "
                      f"HC={'Y' if m['hard_case_flag'] else 'N'}")
                return {"status": "ok", "config": config, "metrics": m}

    # Fallback: no metrics
    print(f"           [WARN] No metrics. RC={result.returncode}")
    if result.stderr:
        for line in result.stderr.strip().split("\n")[-3:]:
            print(f"           stderr: {line}")
    return {"status": "fail", "config": config, "rc": result.returncode}


def main():
    print("=" * 64)
    print("  CPSForge 5-Scene Live Evaluation")
    print(f"  Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 64)

    # PLC probe
    print("\n[1/2] Probing PLC at 192.168.0.1 ...")
    if not probe_plc():
        print("[FAIL] PLC unreachable. Aborting.")
        sys.exit(1)
    print("[OK] PLC is online.\n")

    all_results = []

    for scene_name, fio_num, fio_label in SCENES:
        print("-" * 64)
        print(f"  Scene S{fio_num}: {fio_label}  ({scene_name})")
        print("-" * 64)
        input(f"  >> Load Factory I/O scene '{fio_label}' and press PLAY, then hit Enter ...")

        # Quick re-probe after scene switch
        if not probe_plc():
            print("  [WARN] PLC probe failed after scene switch. Retrying in 3s ...")
            time.sleep(3)
            if not probe_plc():
                print("  [ERROR] PLC still unreachable. Skipping this scene.")
                continue

        for attacker in ATTACKERS:
            try:
                r = run_one(scene_name, attacker)
                all_results.append(r)
            except subprocess.TimeoutExpired:
                print(f"  [{attacker:8s}] TIMEOUT")
                all_results.append({"status": "timeout", "config": f"live_{attacker}_{scene_name}"})
            except Exception as e:
                print(f"  [{attacker:8s}] ERROR: {e}")
                all_results.append({"status": "error", "config": f"live_{attacker}_{scene_name}"})

            # Brief stabilization between runs
            print("  Stabilizing (3s) ...")
            time.sleep(3)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 64)
    print("  SUMMARY")
    print("=" * 64)
    header = f"  {'Config':<42s} {'ASR':>5s} {'F1':>5s} {'Imp':>6s} {'Prec':>5s} {'Rec':>5s} {'Lat':>6s} {'HC':>3s}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for r in all_results:
        cfg = r["config"]
        if r["status"] == "ok":
            m = r["metrics"]
            print(f"  {cfg:<42s} {m['attack_success_rate']:5.2f} {m['detector_f1']:5.2f} "
                  f"{m['process_impact_score']:6.3f} {m['detector_precision']:5.2f} "
                  f"{m['detector_recall']:5.2f} {m['detection_latency_ms']:6.0f} "
                  f"{'Y' if m['hard_case_flag'] else 'N':>3s}")
        else:
            print(f"  {cfg:<42s}  -- {r['status']} --")

    # Generate experiment summaries
    print("\nGenerating experiment summaries ...")
    for r in all_results:
        if r["status"] == "ok":
            subprocess.run(
                [sys.executable, "-m", "cpsforge", "report", "summarize",
                 "--experiment", r["config"]],
                capture_output=True, timeout=30,
            )

    print(f"\nFinished: {time.strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
