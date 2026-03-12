"""Run all 6 live eval experiments sequentially."""
import subprocess
import sys
import json
import time
from pathlib import Path

EXPERIMENTS = [
    ("from_a_to_b", "scripted", "live_scripted_from_a_to_b"),
    ("from_a_to_b", "random", "live_random_from_a_to_b"),
    ("level_control", "scripted", "live_scripted_level_control"),
    ("level_control", "random", "live_random_level_control"),
    ("sorting_height_basic", "scripted", "live_scripted_sorting_height_basic"),
    ("sorting_height_basic", "random", "live_random_sorting_height_basic"),
]

def run_experiment(scene: str, attacker: str, config: str) -> dict:
    """Run one experiment and return result info."""
    cmd = [
        sys.executable, "-m", "cpsforge", "run", "attack",
        "--scene", scene,
        "--attacker", attacker,
        "--experiment", config,
        "--no-dry-run",
        "--eval-run",
        "--yes",
    ]
    print(f"\n{'='*60}")
    print(f"  {attacker} on {scene} ({config})")
    print(f"{'='*60}")
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    
    # Find the run directory
    raw_dir = Path("data/raw") / config
    if raw_dir.exists():
        run_dirs = sorted(raw_dir.iterdir(), key=lambda p: p.name)
        if run_dirs:
            latest = run_dirs[-1]
            metrics_file = latest / "metrics.json"
            if metrics_file.exists():
                metrics = json.loads(metrics_file.read_text())
                print(f"  Run ID: {metrics['run_id']}")
                print(f"  Attack success rate: {metrics['attack_success_rate']}")
                print(f"  Process impact:      {metrics['process_impact_score']}")
                print(f"  Detector F1:         {metrics['detector_f1']}")
                print(f"  Detector precision:  {metrics['detector_precision']}")
                print(f"  Detector recall:     {metrics['detector_recall']}")
                print(f"  Detection latency:   {metrics['detection_latency_ms']} ms")
                print(f"  Hard case flag:      {metrics['hard_case_flag']}")
                return {"status": "success", "config": config, "metrics": metrics}
    
    print(f"  [WARN] No metrics found. RC={result.returncode}")
    if result.stderr:
        # Print last few lines of stderr
        lines = result.stderr.strip().split("\n")
        for line in lines[-5:]:
            print(f"  stderr: {line}")
    
    return {"status": "failed", "config": config, "returncode": result.returncode}


def main():
    print("CPSForge Full Live Evaluation")
    print(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Quick PLC check
    probe = subprocess.run(
        [sys.executable, "-m", "cpsforge", "plc", "probe"],
        capture_output=True, text=True, timeout=30
    )
    if probe.returncode != 0:
        print("[ERROR] PLC probe failed!")
        sys.exit(1)
    print("[OK] PLC is reachable.\n")
    
    results = []
    for scene, attacker, config in EXPERIMENTS:
        try:
            r = run_experiment(scene, attacker, config)
            results.append(r)
        except subprocess.TimeoutExpired:
            print(f"  [ERROR] Timeout for {config}")
            results.append({"status": "timeout", "config": config})
        except Exception as e:
            print(f"  [ERROR] {e}")
            results.append({"status": "error", "config": config, "error": str(e)})
        
        # Brief stabilization pause
        print("  Stabilizing (5s)...")
        time.sleep(5)
    
    # Summary
    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    for r in results:
        status = r["status"]
        config = r["config"]
        if status == "success":
            m = r["metrics"]
            print(f"  {config}: ASR={m['attack_success_rate']:.2f} F1={m['detector_f1']:.2f} Impact={m['process_impact_score']:.3f}")
        else:
            print(f"  {config}: {status}")
    
    # Generate summaries
    print("\nGenerating experiment summaries...")
    for _, _, config in EXPERIMENTS:
        raw_dir = Path("data/raw") / config
        if raw_dir.exists():
            subprocess.run(
                [sys.executable, "-m", "cpsforge", "report", "summarize", "--experiment", config],
                capture_output=True, timeout=30
            )
            print(f"  Summary: {config}")
    
    print(f"\nCompleted at: {time.strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
