#!/usr/bin/env python3
"""Generate attack, defender, and experiment configs for all 21 Factory I/O scenes.

Reads each scene YAML to extract tags, writable tags, attack surface, and safety rules,
then generates scene-specific configs for:
  - 3 attack configs: scripted, random, llm
  - 2 defender configs: threshold, invariant
  - 4 experiment configs: live_scripted, live_random, live_llm, agent

Usage:
    python scripts/generate_all_configs.py
"""
import os
import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCENES_DIR = ROOT / "configs" / "scenes"
ATTACKS_DIR = ROOT / "configs" / "attacks"
DEFENDERS_DIR = ROOT / "configs" / "defenders"
EXPERIMENTS_DIR = ROOT / "configs" / "experiments"

# Scenes that already have all configs — skip
EXISTING = {"from_a_to_b", "level_control", "sorting_height_basic", "tank_control"}


def load_scene(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_tags_by_category(scene: dict) -> dict:
    cats = {}
    for t in scene.get("tags", []):
        cat = t.get("category", "unknown")
        cats.setdefault(cat, []).append(t)
    return cats


def has_real_tags(scene: dict) -> bool:
    return any(t.get("data_type") in ("real",) for t in scene.get("tags", []))


def has_setpoint_tags(scene: dict) -> bool:
    return any(t.get("category") == "setpoint" for t in scene.get("tags", []))


def has_enable_tag(scene: dict) -> bool:
    return any(t.get("name") == "enable" for t in scene.get("tags", []))


def has_state_tag(scene: dict) -> bool:
    return any(t.get("name") in ("state", "i_state") for t in scene.get("tags", []))


def get_attack_types(scene: dict) -> list:
    types = ["actuator_override"]
    if has_real_tags(scene) or has_setpoint_tags(scene):
        types.append("setpoint_shift")
        types.append("sensor_spoof")
    if has_state_tag(scene):
        types.append("sequence_perturbation")
        types.append("timing_delay")
    else:
        types.append("sequence_perturbation")
    return types


def scene_description_for_llm(scene: dict) -> dict:
    """Generate attacker_objective and prompt_notes from scene metadata."""
    name = scene["scene_name"]
    desc = scene.get("description", "").strip()
    writable = scene.get("writable_tags", [])
    attack_surface = scene.get("attack_surface", [])
    cats = get_tags_by_category(scene)

    sensors = [t["name"] for t in cats.get("sensor", [])]
    actuators = [t["name"] for t in cats.get("actuator", [])]
    setpoints = [t["name"] for t in cats.get("setpoint", [])]

    objective = f"Disrupt the {name.replace('_', ' ')} process. {desc} "
    objective += f"Writable targets: {', '.join(attack_surface)}. "

    if has_real_tags(scene):
        objective += "This scene has analog (REAL) values — gradual shifts may evade threshold detectors. "
    if has_enable_tag(scene):
        objective += "The enable flag is never written by PLC logic — disabling it halts the process. "
    if has_state_tag(scene):
        objective += "Try to cause state machine inconsistencies or stuck states. "

    objective += "The defender uses threshold and invariant checks."

    notes = f"Attack surface: {', '.join(attack_surface)}. "
    if setpoints:
        notes += f"Setpoints: {', '.join(setpoints)}. "
    notes += f"Sensors (read-only): {', '.join(sensors[:6])}. "
    notes += f"Actuators: {', '.join(actuators[:6])}."

    return {"attacker_objective": objective, "prompt_notes": notes}


def generate_scripted_attack(scene: dict) -> dict:
    name = scene["scene_name"]
    return {
        "name": f"scripted_{name}",
        "attacker_type": "scripted",
        "scene_name": name,
        "max_actions": 5,
        "inter_attack_delay_ms": 3000,
        "attack_types": get_attack_types(scene),
    }


def generate_random_attack(scene: dict) -> dict:
    name = scene["scene_name"]
    return {
        "name": f"random_{name}",
        "attacker_type": "random",
        "scene_name": name,
        "max_actions": 10,
        "inter_attack_delay_ms": 2000,
        "attack_types": get_attack_types(scene),
        "random_seed": 42,
        "value_noise_std": 0.1,
    }


def generate_llm_attack(scene: dict) -> dict:
    name = scene["scene_name"]
    llm_desc = scene_description_for_llm(scene)
    return {
        "name": f"llm_{name}",
        "attacker_type": "llm",
        "scene_name": name,
        "llm_provider": "local_openai_compatible",
        "llm_model": None,
        "llm_max_retries": 3,
        "multi_step": False,
        "max_actions": 3 if has_real_tags(scene) else 2,
        "inter_attack_delay_ms": 2000 if not has_real_tags(scene) else 3000,
        "attack_types": get_attack_types(scene),
        "parameters": llm_desc,
    }


def generate_threshold_defender(scene: dict) -> dict:
    name = scene["scene_name"]
    thresholds = []

    for t in scene.get("tags", []):
        tag_name = t["name"]
        dtype = t.get("data_type", "bool")
        cat = t.get("category", "")
        min_v = t.get("min_value")
        max_v = t.get("max_value")

        # Enable flag off
        if tag_name == "enable":
            thresholds.append({
                "tag": "enable",
                "operator": "==",
                "value": 0,
                "severity": "high",
                "label": "enable_off",
                "description": "System enable flag is FALSE — process halted",
            })
            continue

        # State machine bounds
        if tag_name in ("state", "i_state") and max_v is not None:
            thresholds.append({
                "tag": tag_name,
                "operator": ">",
                "value": max_v,
                "severity": "high",
                "label": f"invalid_{tag_name}_high",
                "description": f"State machine value exceeds max ({max_v})",
            })
            if min_v is not None:
                thresholds.append({
                    "tag": tag_name,
                    "operator": "<",
                    "value": min_v,
                    "severity": "high",
                    "label": f"invalid_{tag_name}_low",
                    "description": f"State machine value below min ({min_v})",
                })
            continue

        # REAL sensors with range
        if dtype == "real" and cat == "sensor" and max_v is not None:
            hi_thresh = max_v * 0.9
            lo_thresh = max_v * 0.05 if min_v is not None and min_v >= 0 else (min_v + 0.5 if min_v is not None else None)
            thresholds.append({
                "tag": tag_name,
                "operator": ">",
                "value": round(hi_thresh, 1),
                "severity": "high",
                "label": f"{tag_name}_high",
                "description": f"{tag_name} exceeds 90% of max ({max_v})",
            })
            if lo_thresh is not None:
                thresholds.append({
                    "tag": tag_name,
                    "operator": "<",
                    "value": round(lo_thresh, 1),
                    "severity": "high",
                    "label": f"{tag_name}_low",
                    "description": f"{tag_name} below safe minimum",
                })

        # REAL setpoints with range
        if dtype == "real" and cat == "setpoint" and max_v is not None:
            thresholds.append({
                "tag": tag_name,
                "operator": ">",
                "value": round(max_v * 0.9, 1),
                "severity": "medium",
                "label": f"{tag_name}_high",
                "description": f"Setpoint {tag_name} near maximum",
            })
            if min_v is not None:
                thresholds.append({
                    "tag": tag_name,
                    "operator": "<",
                    "value": round(min_v + (max_v - min_v) * 0.1, 1),
                    "severity": "medium",
                    "label": f"{tag_name}_low",
                    "description": f"Setpoint {tag_name} near minimum",
                })

        # INT range checks (counts, slots, etc.)
        if dtype in ("int", "dint") and cat in ("setpoint", "internal") and max_v is not None and tag_name not in ("state", "i_state"):
            thresholds.append({
                "tag": tag_name,
                "operator": ">",
                "value": max_v,
                "severity": "high",
                "label": f"{tag_name}_exceeds_max",
                "description": f"{tag_name} exceeds max ({max_v})",
            })

    # Add actuator-stopped checks for key writable actuators (first 2 bool actuators)
    writable = scene.get("writable_tags", [])
    bool_actuators = [t for t in scene.get("tags", [])
                      if t["name"] in writable
                      and t.get("data_type") == "bool"
                      and t.get("category") == "actuator"
                      and t["name"] != "enable"]
    for act in bool_actuators[:2]:
        thresholds.append({
            "tag": act["name"],
            "operator": "==",
            "value": 0,
            "severity": "medium",
            "label": f"{act['name']}_stopped",
            "description": f"{act['name']} is stopped — possible actuator override",
        })

    if not thresholds:
        # Fallback: at least add something for a writable bool
        for w in writable[:1]:
            thresholds.append({
                "tag": w,
                "operator": "==",
                "value": 0,
                "severity": "medium",
                "label": f"{w}_off",
                "description": f"{w} is off — potential attack",
            })

    return {
        "name": f"threshold_{name}",
        "detector_type": "threshold",
        "scene_name": name,
        "enabled": True,
        "thresholds": thresholds,
    }


def generate_invariant_defender(scene: dict) -> dict:
    name = scene["scene_name"]
    rules = []
    rule_num = 1
    prefix = "".join(w[0].upper() for w in name.split("_"))

    # Generate from safety_rules (mutual exclusion → invariant)
    for sr in scene.get("safety_rules", []):
        if sr.get("rule_type") == "mutual_exclusion":
            tags = sr.get("tags", [])
            if len(tags) == 2:
                rules.append({
                    "rule_id": f"{prefix}-INV-{rule_num:03d}",
                    "description": sr.get("description", f"{tags[0]} and {tags[1]} mutual exclusion"),
                    "condition": f"NOT ({tags[0]} == True AND {tags[1]} == True)",
                    "tags": tags,
                    "severity": "critical",
                    "label": f"{tags[0]}_{tags[1]}_conflict",
                })
                rule_num += 1

    # Enable + actuator invariant
    if has_enable_tag(scene):
        # Get first bool actuator
        writable = scene.get("writable_tags", [])
        bool_acts = [t["name"] for t in scene.get("tags", [])
                     if t["name"] in writable
                     and t.get("data_type") == "bool"
                     and t.get("category") == "actuator"
                     and t["name"] != "enable"]
        if bool_acts:
            act = bool_acts[0]
            rules.append({
                "rule_id": f"{prefix}-INV-{rule_num:03d}",
                "description": f"Enable must be on when {act} is active",
                "condition": f"NOT (enable == False AND {act} == True)",
                "tags": ["enable", act],
                "severity": "high",
                "label": f"enable_off_with_{act}",
            })
            rule_num += 1

    # State-based invariants
    if has_state_tag(scene):
        state_tag = "state" if any(t["name"] == "state" for t in scene.get("tags", [])) else "i_state"
        state_t = next((t for t in scene.get("tags", []) if t["name"] == state_tag), None)
        if state_t and state_t.get("max_value") is not None:
            rules.append({
                "rule_id": f"{prefix}-INV-{rule_num:03d}",
                "description": f"State must be within valid range [0, {state_t['max_value']}]",
                "condition": f"NOT ({state_tag} < 0 OR {state_tag} > {state_t['max_value']})",
                "tags": [state_tag],
                "severity": "high",
                "label": f"invalid_{state_tag}_range",
            })
            rule_num += 1

    # REAL range invariants for setpoints
    for t in scene.get("tags", []):
        if t.get("data_type") == "real" and t.get("category") == "setpoint":
            min_v = t.get("min_value", 0)
            max_v = t.get("max_value")
            if max_v is not None:
                rules.append({
                    "rule_id": f"{prefix}-INV-{rule_num:03d}",
                    "description": f"{t['name']} must be in [{min_v}, {max_v}]",
                    "condition": f"NOT ({t['name']} < {min_v} OR {t['name']} > {max_v})",
                    "tags": [t["name"]],
                    "severity": "high",
                    "label": f"{t['name']}_out_of_range",
                })
                rule_num += 1

    if not rules:
        # Fallback
        writable = scene.get("writable_tags", [])
        if len(writable) >= 2:
            rules.append({
                "rule_id": f"{prefix}-INV-001",
                "description": f"Baseline: at least one writable tag should be active",
                "condition": f"NOT ({writable[0]} == False AND {writable[1]} == False)",
                "tags": writable[:2],
                "severity": "medium",
                "label": "all_actuators_off",
            })

    return {
        "name": f"invariant_{name}",
        "detector_type": "invariant",
        "scene_name": name,
        "enabled": True,
        "invariant_rules": rules,
    }


def generate_experiment(scene: dict, exp_type: str) -> dict:
    name = scene["scene_name"]
    has_reals = has_real_tags(scene)

    if exp_type == "live_scripted":
        return {
            "name": f"live_scripted_{name}",
            "description": f"Live eval run: scripted attacker vs threshold + invariant detectors on {name.replace('_', ' ')}.",
            "scene_config": f"scenes/{name}.yaml",
            "plc_config": "system/plc.yaml",
            "attackers": [f"scripted_{name}"],
            "defenders": [f"threshold_{name}", f"invariant_{name}"],
            "live_writes_enabled": True,
            "dry_run": False,
            "eval_run": True,
            "max_steps": 150 if has_reals else 120,
            "run_duration_s": 150.0 if has_reals else 120.0,
            "save_trace": True,
            "save_metrics": True,
            "reset_after_run": True,
        }
    elif exp_type == "live_random":
        return {
            "name": f"live_random_{name}",
            "description": f"Live eval run: random attacker vs threshold + invariant detectors on {name.replace('_', ' ')}.",
            "scene_config": f"scenes/{name}.yaml",
            "plc_config": "system/plc.yaml",
            "attackers": [f"random_{name}"],
            "defenders": [f"threshold_{name}", f"invariant_{name}"],
            "live_writes_enabled": True,
            "dry_run": False,
            "eval_run": True,
            "max_steps": 200,
            "run_duration_s": 180.0,
            "save_trace": True,
            "save_metrics": True,
            "reset_after_run": True,
        }
    elif exp_type == "live_llm":
        return {
            "name": f"live_llm_{name}",
            "description": f"Live eval run: LLM batch attacker vs threshold + invariant detectors on {name.replace('_', ' ')}.",
            "scene_config": f"scenes/{name}.yaml",
            "plc_config": "system/plc.yaml",
            "attackers": [f"llm_{name}"],
            "defenders": [f"threshold_{name}", f"invariant_{name}"],
            "live_writes_enabled": True,
            "dry_run": False,
            "eval_run": True,
            "max_steps": 150,
            "run_duration_s": 150.0,
            "save_trace": True,
            "save_metrics": True,
            "reset_after_run": True,
        }
    elif exp_type == "agent":
        return {
            "name": f"agent_{name}",
            "description": f"Live attacker and defender agents on {name.replace('_', ' ')}.",
            "mode": "agent",
            "scene_config": f"scenes/{name}.yaml",
            "plc_config": "system/plc.yaml",
            "attackers": [],
            "defenders": [f"threshold_{name}", f"invariant_{name}"],
            "attacker_agent": "attacker_agent",
            "defender_agent": "defender_agent",
            "live_writes_enabled": True,
            "dry_run": False,
            "eval_run": True,
            "max_steps": 200,
            "run_duration_s": None,
            "save_trace": True,
            "save_metrics": True,
            "reset_after_run": True,
        }


def write_yaml(data: dict, path: Path, header: str = ""):
    with open(path, "w", encoding="utf-8") as f:
        if header:
            f.write(header + "\n")
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    return path


def make_header(title: str) -> str:
    line = "=" * 77
    return f"# {line}\n# CPSForge {title}\n# {line}"


def main():
    scene_files = sorted(SCENES_DIR.glob("*.yaml"))
    created = []
    skipped = []

    for sf in scene_files:
        scene = load_scene(sf)
        name = scene["scene_name"]

        if name in EXISTING:
            skipped.append(name)
            continue

        # --- Attacks ---
        for gen_func, prefix, label in [
            (generate_scripted_attack, "scripted", "Attack Policy — Scripted"),
            (generate_random_attack, "random", "Attack Policy — Random"),
            (generate_llm_attack, "llm", "Attack Policy — LLM"),
        ]:
            data = gen_func(scene)
            out = ATTACKS_DIR / f"{prefix}_{name}.yaml"
            if not out.exists():
                write_yaml(data, out, make_header(f"{label} ({name.replace('_', ' ').title()})"))
                created.append(str(out.relative_to(ROOT)))

        # --- Defenders ---
        for gen_func, prefix, label in [
            (generate_threshold_defender, "threshold", "Defender — Threshold"),
            (generate_invariant_defender, "invariant", "Defender — Invariant"),
        ]:
            data = gen_func(scene)
            out = DEFENDERS_DIR / f"{prefix}_{name}.yaml"
            if not out.exists():
                write_yaml(data, out, make_header(f"{label} ({name.replace('_', ' ').title()})"))
                created.append(str(out.relative_to(ROOT)))

        # --- Experiments ---
        for exp_type, label in [
            ("live_scripted", "Live Eval — Scripted"),
            ("live_random", "Live Eval — Random"),
            ("live_llm", "Live Eval — LLM"),
            ("agent", "Agent Mode"),
        ]:
            data = generate_experiment(scene, exp_type)
            fname = f"{exp_type}_{name}.yaml" if exp_type != "agent" else f"agent_{name}.yaml"
            out = EXPERIMENTS_DIR / fname
            if not out.exists():
                write_yaml(data, out, make_header(f"{label} ({name.replace('_', ' ').title()})"))
                created.append(str(out.relative_to(ROOT)))

    print(f"\nSkipped (already exist): {len(skipped)} scenes: {', '.join(skipped)}")
    print(f"Created: {len(created)} config files\n")
    for c in sorted(created):
        print(f"  {c}")


if __name__ == "__main__":
    main()
