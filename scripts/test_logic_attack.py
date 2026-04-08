"""
test_logic_attack.py — Quick test of the LLM-driven logic attack pipeline.

Tests the LogicMITMAttacker on Level Control:
  1. Load scene + LLM
  2. LLM generates adversarial SCL modification
  3. Validate that original_code matches the real SCL
  4. Show the proposed modification
  5. Optionally deploy via TIA Openness (--deploy flag)

Usage:
  py -3 scripts/test_logic_attack.py                    # Generate only (safe)
  py -3 scripts/test_logic_attack.py --deploy           # Generate + deploy to TIA
  py -3 scripts/test_logic_attack.py --context minimal  # Use minimal context
  py -3 scripts/test_logic_attack.py --context full     # Use full context (needs PLC)
"""

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpsforge.attacker.logic_mitm import LogicMITMAttacker, _BLOCK_NAMES, _SCL_NAMES
from cpsforge.context_builder.schema import ContextLevel
from cpsforge.core.config import ConfigLoader
from cpsforge.observation.history_buffer import HistoryBuffer
from cpsforge.observation.phase_inference import PhaseInferenceEngine
from cpsforge.scenes.factory import load_scene

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("test_logic_attack")


def main():
    parser = argparse.ArgumentParser(description="Test LLM-driven logic attack")
    parser.add_argument("--scene", default="level_control", help="Scene name")
    parser.add_argument("--context", default="partial", choices=["minimal", "partial", "full"])
    parser.add_argument("--deploy", action="store_true", help="Deploy to TIA Portal")
    parser.add_argument("--restore", action="store_true", help="Restore original after deploy")
    args = parser.parse_args()

    loader = ConfigLoader()
    scene = load_scene(args.scene, loader)
    history = HistoryBuffer(max_size=50)
    phase_engine = PhaseInferenceEngine(args.scene)

    # Build LLM provider
    llm_config = loader.load_llm("huggingface")
    from cpsforge.llm.huggingface_provider import HuggingFaceProvider
    llm_provider = HuggingFaceProvider(llm_config)
    logger.info("Loading model weights...")
    llm_provider._ensure_loaded()
    logger.info("Model loaded.")

    # Create attacker
    context_level = ContextLevel(args.context)
    attacker = LogicMITMAttacker(
        scene=scene,
        llm_provider=llm_provider,
        context_level=context_level,
        history=history,
        phase_engine=phase_engine,
    )

    # Generate attack
    logger.info("Generating logic attack (context=%s)...", args.context)
    result = attacker.generate_attack(snapshot=None)

    print("\n" + "=" * 70)
    print(f"LOGIC ATTACK RESULT (scene={args.scene}, context={args.context})")
    print("=" * 70)
    print(f"Parse success:     {result.parse_success}")
    print(f"Original matched:  {result.original_code_matched}")
    print(f"LLM latency:       {result.llm_latency_ms:.0f} ms")

    if result.modification:
        mod = result.modification
        print(f"\nModification type:  {mod.modification_type}")
        print(f"Expected effect:    {mod.expected_effect}")
        print(f"Detection diff:     {mod.detection_difficulty}")
        print(f"Confidence:         {getattr(mod, 'detection_difficulty', 'N/A')}")
        print(f"\n--- ORIGINAL CODE ---")
        print(mod.original_code)
        print(f"\n--- MODIFIED CODE ---")
        print(mod.modified_code)
        print(f"\n--- REASONING ---")
        print(mod.reasoning)
    else:
        print(f"\nNo modification generated.")
        print(f"Error: {result.error}")

    if not result.success:
        print(f"\nATTACK GENERATION FAILED: {result.error}")
        if result.modification and not result.original_code_matched:
            print("The LLM's original_code field did not match the actual SCL source.")
            print("This is a common issue — the LLM approximates but doesn't quote exactly.")
        return

    # Deploy if requested
    if args.deploy and result.modification:
        print("\n--- DEPLOYING TO TIA PORTAL ---")
        from cpsforge.plc.tia_openness import TiaOpennessClient

        tia = TiaOpennessClient()
        if not tia.attach():
            print("ERROR: Cannot attach to TIA Portal")
            return

        # Backup
        block_name = _BLOCK_NAMES.get(args.scene, f"FB_{args.scene}")
        backup = tia.backup_block(block_name)
        print(f"Backup: {backup}")

        # Apply and deploy
        original_scl = attacker.get_scl_source(args.scene)
        modified_scl = attacker.apply_modification(original_scl, result.modification)

        if modified_scl is None:
            print("ERROR: Could not apply modification")
            return

        source_name = _SCL_NAMES.get(args.scene)
        ok, msg = tia.deploy_scl(modified_scl, source_name)
        print(f"Deploy: success={ok}, message={msg}")

        if ok:
            print("\nModified code compiled successfully!")
            print("Download to PLC from TIA Portal: Online → Download to device → Load")

        if args.restore:
            print("\nRestoring original...")
            ok2, msg2 = tia.restore_block(
                block_name, Path("factoryio_scenes") / source_name,
            )
            print(f"Restore: success={ok2}, message={msg2}")


if __name__ == "__main__":
    main()
