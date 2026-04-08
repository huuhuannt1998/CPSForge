"""
run_logic_analysis.py — Run LLM-based SCL vulnerability analysis on all 3 evaluation scenes.

This script runs the LogicAnalyzer on each scene's SCL source code, producing:
  - Vulnerability reports (static analysis)
  - Adversarial code modifications (7 categories each)

Results are saved as JSON to data/processed/logic_analysis/.

Usage:
  py -3 scripts/run_logic_analysis.py
  py -3 scripts/run_logic_analysis.py --scenes level_control sorting_weight
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

SCENES = {
    "level_control": {
        "description": "PID-controlled water tank. Fill valve and discharge valve regulate level to setpoint. Continuous analog control.",
    },
    "sorting_weight": {
        "description": "Weight-based sorting station. Items weighed, classified as light/medium/heavy, routed to 3 exits via state machine.",
    },
    "sorting_height_basic": {
        "description": "Height-based binary sort. Items classified as tall/short via vision sensor, routed to left/right exit via state machine.",
    },
}


def main():
    parser = argparse.ArgumentParser(description="Run SCL logic vulnerability analysis")
    parser.add_argument("--scenes", nargs="+", default=list(SCENES.keys()),
                        help="Scenes to analyze (default: all 3)")
    parser.add_argument("--output-dir", type=str, default="data/processed/logic_analysis",
                        help="Output directory for results")
    parser.add_argument("--llm", type=str, default="huggingface",
                        help="LLM config name (default: huggingface)")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load LLM provider
    from cpsforge.core.config import ConfigLoader
    from cpsforge.llm.factory import build_provider
    from cpsforge.attacker.logic_analyzer import LogicAnalyzer

    loader = ConfigLoader(configs_dir=Path("configs"))
    llm_cfg = loader.load_llm(args.llm)

    print(f"Loading LLM: {llm_cfg.model} (provider: {llm_cfg.provider})...")
    provider = build_provider(llm_cfg)
    analyzer = LogicAnalyzer(llm_provider=provider, scl_dir=Path("factoryio_scenes"))

    total_t0 = time.monotonic()
    all_results = {}

    for scene_name in args.scenes:
        if scene_name not in SCENES:
            print(f"WARNING: Unknown scene '{scene_name}', skipping")
            continue

        scene_info = SCENES[scene_name]
        print(f"\n{'='*60}")
        print(f"Analyzing: {scene_name}")
        print(f"{'='*60}")

        t0 = time.monotonic()
        report = analyzer.analyze_scene(
            scene_name=scene_name,
            scene_description=scene_info["description"],
        )
        elapsed = time.monotonic() - t0

        # Save individual report
        report_path = output_dir / f"{scene_name}_analysis.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report.as_dict(), f, indent=2, ensure_ascii=False)

        # Summary
        n_vulns = len(report.vulnerabilities)
        n_mods = len(report.modifications)
        n_parsed = sum(1 for m in report.modifications if m.parse_success)

        print(f"  Vulnerabilities found: {n_vulns}")
        print(f"  Modifications generated: {n_mods} ({n_parsed} parsed successfully)")
        print(f"  Total analysis time: {elapsed:.1f}s")

        for v in report.vulnerabilities[:5]:
            print(f"    - [{v.get('severity', '?')}] {v.get('description', '?')[:80]}")

        for m in report.modifications:
            status = "OK" if m.parse_success else "FAIL"
            print(f"    [{status}] {m.modification_type}: {m.expected_effect[:60]}...")

        all_results[scene_name] = {
            "vulnerabilities": n_vulns,
            "modifications": n_mods,
            "parsed": n_parsed,
            "elapsed_s": round(elapsed, 1),
        }

    total_elapsed = time.monotonic() - total_t0

    # Save summary
    summary_path = output_dir / "analysis_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({
            "scenes": all_results,
            "total_elapsed_s": round(total_elapsed, 1),
            "model": str(llm_cfg.model),
        }, f, indent=2)

    print(f"\n{'='*60}")
    print(f"COMPLETE — {len(all_results)} scenes analyzed in {total_elapsed:.1f}s")
    print(f"Results saved to: {output_dir}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
