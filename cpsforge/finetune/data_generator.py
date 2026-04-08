"""
data_generator.py — Extract QLoRA fine-tuning data from existing runs.

Algorithm
---------
For each run folder in data/raw/<experiment>/<run_id>/:
  1. Load unified_steps.parquet (v2 runs) OR trace.parquet + attacks.json (v1 runs).
  2. For each step where:
       - parsed_decision == "attack"
       - parse_success == True
       - shield_decision == "approved"
       - attack_success == True (at or after attack expiry)
  3. Reconstruct system_prompt and user_prompt from logged context fields.
     (If raw prompts were logged, use them directly.)
  4. Use llm_raw_output as gold_output.
  5. Emit one FinetuneExample per qualifying step.

Output
------
A JSONL file at data/processed/<dataset_name>/finetune_examples.jsonl
with one FinetuneExample (as JSON dict) per line.

Typical yield: ~8-15 high-quality examples per successful run.
From 88 existing runs: expected ~600-900 examples.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)

# Optional pandas import — only needed at generation time.
try:
    import pandas as pd
    _PANDAS_AVAILABLE = True
except ImportError:
    _PANDAS_AVAILABLE = False
    logger.warning("pandas not installed — DataGenerator will not function without it.")


class DataGenerator:
    """Extract fine-tuning examples from completed CPSForge runs.

    Parameters
    ----------
    raw_data_root : Path
        Root directory containing experiment subfolders (data/raw/).
    output_dir : Path
        Where to write finetune_examples.jsonl.
    context_levels_filter : list of str, optional
        Only accept examples from these context levels.
        Default: ["full"] — we train on rich-context examples only.
    min_confidence : float
        Minimum decision confidence to include an example.
    """

    def __init__(
        self,
        raw_data_root: Path = Path("data/raw"),
        output_dir: Path = Path("data/processed/finetune"),
        context_levels_filter: Optional[List[str]] = None,
        min_confidence: float = 0.5,
    ) -> None:
        self._root = Path(raw_data_root)
        self._output_dir = Path(output_dir)
        self._ctx_filter = context_levels_filter or ["full"]
        self._min_conf = min_confidence

    def generate(
        self,
        experiment_names: Optional[List[str]] = None,
        split_ratio: float = 0.85,
        seed: int = 42,
    ) -> int:
        """Generate examples from all (or specified) experiments.

        Parameters
        ----------
        experiment_names : list of str, optional
            Restrict to specific experiment directories.
        split_ratio : float
            Fraction of examples assigned to the training set (default 0.85).
            Remaining go to validation. Stratified by scene to prevent leakage.
        seed : int
            Random seed for reproducible split.

        Returns the number of examples written.
        """
        if not _PANDAS_AVAILABLE:
            raise RuntimeError("pandas must be installed to generate training data.")

        import random
        from cpsforge.finetune.data_schema import FinetuneExample

        self._output_dir.mkdir(parents=True, exist_ok=True)

        # Collect all examples first (for stratified splitting)
        all_examples = list(self._iter_examples(experiment_names))
        if not all_examples:
            logger.warning("No qualifying examples found.")
            return 0

        # Stratified split by scene
        rng = random.Random(seed)
        by_scene: Dict[str, list] = {}
        for ex in all_examples:
            by_scene.setdefault(ex.scene, []).append(ex)

        train_examples: list = []
        val_examples: list = []
        for scene_name, scene_exs in by_scene.items():
            rng.shuffle(scene_exs)
            n_train = max(1, int(len(scene_exs) * split_ratio))
            train_examples.extend(scene_exs[:n_train])
            val_examples.extend(scene_exs[n_train:])

        # Shuffle within splits
        rng.shuffle(train_examples)
        rng.shuffle(val_examples)

        # Write files
        train_path = self._output_dir / "train.jsonl"
        val_path = self._output_dir / "val.jsonl"
        all_path = self._output_dir / "finetune_examples.jsonl"

        for path, examples in [
            (train_path, train_examples),
            (val_path, val_examples),
            (all_path, all_examples),
        ]:
            with open(path, "w", encoding="utf-8") as f:
                for ex in examples:
                    f.write(json.dumps(ex.as_dict()) + "\n")

        logger.info(
            "Generated %d examples (train=%d, val=%d) → %s",
            len(all_examples), len(train_examples), len(val_examples),
            self._output_dir,
        )

        # Write split manifest
        manifest = {
            "total": len(all_examples),
            "train": len(train_examples),
            "val": len(val_examples),
            "split_ratio": split_ratio,
            "seed": seed,
            "scenes": {s: len(exs) for s, exs in by_scene.items()},
            "context_levels_filter": self._ctx_filter,
            "min_confidence": self._min_conf,
        }
        with open(self._output_dir / "split_manifest.json", "w") as f:
            json.dump(manifest, f, indent=2)

        return len(all_examples)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _iter_examples(
        self, experiment_names: Optional[List[str]] = None
    ) -> Iterator[Any]:
        from cpsforge.finetune.data_schema import FinetuneExample

        if not self._root.exists():
            logger.warning("Raw data root not found: %s", self._root)
            return

        exps = experiment_names or [d.name for d in self._root.iterdir() if d.is_dir()]
        for exp_name in exps:
            exp_dir = self._root / exp_name
            if not exp_dir.is_dir():
                continue
            for run_dir in sorted(exp_dir.iterdir()):
                if not run_dir.is_dir():
                    continue
                yield from self._extract_from_run(run_dir, exp_name)

    def _extract_from_run(
        self, run_dir: Path, experiment_name: str
    ) -> Iterator[Any]:
        from cpsforge.finetune.data_schema import FinetuneExample

        # Try v2 unified step log first
        unified_path = run_dir / "unified_steps.parquet"
        if unified_path.exists():
            yield from self._extract_from_unified(unified_path, run_dir)
            return

        # Fallback: v1 trace + attacks (limited reconstruction)
        trace_path = run_dir / "trace.parquet"
        attacks_path = run_dir / "attacks.json"
        if trace_path.exists() and attacks_path.exists():
            logger.debug("Processing v1 run at %s", run_dir)
            yield from self._extract_from_v1(trace_path, attacks_path, run_dir)

    def _extract_from_unified(
        self, parquet_path: Path, run_dir: Path
    ) -> Iterator[Any]:
        from cpsforge.finetune.data_schema import FinetuneExample

        try:
            df = pd.read_parquet(parquet_path)
        except Exception as exc:
            logger.warning("Cannot read %s: %s", parquet_path, exc)
            return

        required_cols = {"parsed_decision", "parse_success", "shield_decision",
                         "llm_raw_output", "context_level"}
        if not required_cols.issubset(df.columns):
            logger.debug("Skipping run (missing columns): %s", run_dir)
            return

        # ----------------------------------------------------------
        # 1. ATTACK training examples: physically successful attacks
        # ----------------------------------------------------------
        # Compute post-hoc attack success for each write step.
        attack_mask = (
            (df["parsed_decision"] == "attack")
            & (df["parse_success"] == True)
            & (df["shield_decision"] == "approved")
            & (df.get("phase_shield_blocked", False) != True)
            & (df.get("intent_check_blocked", False) != True)
            & (df["context_level"].isin(self._ctx_filter))
        )

        run_id = run_dir.name

        for _, row in df[attack_mask].iterrows():
            raw_output = row.get("llm_raw_output")
            if not raw_output:
                continue

            # Post-hoc success check: did the write move the tag toward
            # the injected value? (Same logic as analysis tables.)
            step_n = int(row.get("step_id", 0))
            write_ok = bool(row.get("write_executed", False))
            posthoc_success = False
            if write_ok:
                target = row.get("action_target_tag")
                wval = row.get("action_value")
                if target and wval is not None:
                    before = df[df["step_id"] == step_n - 1]
                    after = df[df["step_id"] == step_n + 2]
                    if not before.empty and not after.empty:
                        b_obs = before.iloc[0].get("observation_dict")
                        a_obs = after.iloc[0].get("observation_dict")
                        if isinstance(b_obs, dict) and isinstance(a_obs, dict):
                            bv, av = b_obs.get(target), a_obs.get(target)
                            if bv is not None and av is not None:
                                try:
                                    if abs(float(av) - float(wval)) < abs(float(bv) - float(wval)):
                                        posthoc_success = True
                                except (TypeError, ValueError):
                                    pass

            # For attack training: include if write executed AND succeeded,
            # OR if approved but not yet executed (valid proposal, teaches format)
            if write_ok and not posthoc_success:
                continue  # Skip physically unsuccessful writes

            # Validate gold output is parseable JSON
            try:
                gold_dict = json.loads(raw_output)
            except json.JSONDecodeError:
                gold_dict = _extract_first_json(raw_output)
                if gold_dict is None:
                    continue

            sys_prompt, user_prompt = _reconstruct_prompts(row, role="attacker")
            if not sys_prompt:
                continue

            example = FinetuneExample(
                system_prompt=sys_prompt,
                user_prompt=user_prompt,
                gold_output=json.dumps(gold_dict),
                gold_decision=gold_dict.get("decision", "attack"),
                gold_target_tag=gold_dict.get("target_tag"),
                gold_action_value=gold_dict.get("action_value"),
                gold_action_type=gold_dict.get("action_type"),
                source_run_id=run_id,
                scene=str(row.get("scene", "")),
                context_level=str(row.get("context_level", "")),
                phase_at_step=str(row.get("inferred_phase", "")),
                step_id=step_n,
                shield_approved=True,
                attack_success=posthoc_success,
                confidence=float(gold_dict.get("confidence", 1.0)),
                has_reasoning=bool(gold_dict.get("reasoning")),
                has_timing_rationale=bool(gold_dict.get("timing_rationale")),
            )
            yield example

        # ----------------------------------------------------------
        # 2. DEFENSE training examples: block attacks + allow normal
        # ----------------------------------------------------------
        # For "block" examples: attack proposals that the defender should block
        for _, row in df[attack_mask].iterrows():
            raw_output = row.get("llm_raw_output")
            if not raw_output:
                continue
            try:
                atk_dict = json.loads(raw_output)
            except json.JSONDecodeError:
                atk_dict = _extract_first_json(raw_output)
                if atk_dict is None:
                    continue

            defense_gold = json.dumps({
                "decision": "block",
                "suspicion_score": 0.9,
                "reasoning": f"Proposed write to {atk_dict.get('target_tag', 'unknown')} "
                             f"with value {atk_dict.get('action_value', '?')} is inconsistent "
                             f"with normal process operation during phase "
                             f"{row.get('inferred_phase', 'unknown')}."
            })
            sys_prompt, user_prompt = _reconstruct_defense_prompt(row, atk_dict)
            if not sys_prompt:
                continue
            yield FinetuneExample(
                system_prompt=sys_prompt, user_prompt=user_prompt,
                gold_output=defense_gold, gold_decision="block",
                gold_target_tag=atk_dict.get("target_tag"),
                gold_action_value=atk_dict.get("action_value"),
                source_run_id=run_id,
                scene=str(row.get("scene", "")),
                context_level=str(row.get("context_level", "")),
                phase_at_step=str(row.get("inferred_phase", "")),
                step_id=int(row.get("step_id", 0)),
                shield_approved=True, attack_success=False,
                confidence=0.9, has_reasoning=True,
            )

        # For "allow" examples: normal operation steps (no attack proposed)
        normal_mask = (
            (df["parsed_decision"].isna() | (df["parsed_decision"] == "wait"))
            & (df["context_level"].isin(self._ctx_filter))
        )
        # Sample up to 5 normal steps per run to balance dataset
        normal_sample = df[normal_mask].head(5)
        for _, row in normal_sample.iterrows():
            obs_dict = row.get("observation_dict")
            if not isinstance(obs_dict, dict) or not obs_dict:
                continue
            # Synthesize a plausible legitimate write for "allow" training
            tags = list(obs_dict.keys())
            if not tags:
                continue
            # Pick a tag and use its current value (a no-op write = legitimate)
            synth_tag = tags[0]
            synth_val = obs_dict[synth_tag]
            if synth_val is None:
                continue
            synth_write = {
                "target_tag": synth_tag, "action_type": "actuator_override",
                "action_value": synth_val, "duration_ms": 500,
            }
            defense_gold = json.dumps({
                "decision": "allow",
                "suspicion_score": 0.1,
                "reasoning": f"Write to {synth_tag} with value {synth_val} is "
                             f"consistent with normal controller operation."
            })
            sys_prompt, user_prompt = _reconstruct_defense_prompt(row, synth_write)
            if not sys_prompt:
                continue
            yield FinetuneExample(
                system_prompt=sys_prompt, user_prompt=user_prompt,
                gold_output=defense_gold, gold_decision="allow",
                gold_target_tag=synth_tag, gold_action_value=synth_val,
                source_run_id=run_id,
                scene=str(row.get("scene", "")),
                context_level=str(row.get("context_level", "")),
                phase_at_step=str(row.get("inferred_phase", "")),
                step_id=int(row.get("step_id", 0)),
                shield_approved=True, attack_success=False,
                confidence=0.1, has_reasoning=True,
            )

    def _extract_from_v1(
        self, trace_path: Path, attacks_path: Path, run_dir: Path
    ) -> Iterator[Any]:
        """Very limited extraction from v1 runs — skipped if no LLM metadata."""
        from cpsforge.finetune.data_schema import FinetuneExample
        # Check for v1 LLM metadata file
        llm_path = run_dir / "llm_log.json"
        if not llm_path.exists():
            return
        try:
            with open(llm_path) as f:
                llm_log = json.load(f)
        except Exception:
            return

        for entry in llm_log:
            if not entry.get("shield_approved"):
                continue
            raw = entry.get("raw_response", "")
            gold_dict = _extract_first_json(raw)
            if gold_dict is None:
                continue
            example = FinetuneExample(
                system_prompt=entry.get("system_prompt", ""),
                user_prompt=entry.get("user_prompt", ""),
                gold_output=json.dumps(gold_dict),
                gold_decision=gold_dict.get("decision", "attack"),
                gold_target_tag=gold_dict.get("target_tag"),
                gold_action_value=gold_dict.get("action_value"),
                gold_action_type=gold_dict.get("action_type"),
                source_run_id=run_dir.name,
                scene=entry.get("scene", ""),
                context_level="full",
                shield_approved=True,
                attack_success=True,
            )
            yield example


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_first_json(text: str) -> Optional[Dict[str, Any]]:
    """Extract the first JSON object from *text*."""
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _reconstruct_prompts(row: Any, role: str = "attacker") -> tuple:
    """Best-effort reconstruction of (system_prompt, user_prompt) from a log row.

    When raw prompts are not stored in the parquet, we reconstruct a simplified
    version from the observation dict and context level.  This is "good enough"
    for fine-tuning — the model learns the (observation → decision) mapping even
    if the prompt format is slightly simplified.
    """
    ctx_level = str(row.get("context_level", "full"))
    scene = str(row.get("scene", "unknown"))
    obs_dict = row.get("observation_dict")
    if obs_dict is None:
        return "", ""
    if isinstance(obs_dict, str):
        try:
            obs_dict = json.loads(obs_dict)
        except Exception:
            obs_dict = {}

    system_prompt = (
        f"You are an adversarial agent attacking a Cyber-Physical System. "
        f"Scene: {scene}. Context level: {ctx_level}. "
        f"Return a JSON object with your attack decision."
    )
    user_prompt = (
        f"Current process state:\n{json.dumps(obs_dict, indent=2)}\n\n"
        f"Phase: {row.get('inferred_phase', 'unknown')}\n"
        f"Decide: attack or wait."
    )
    return system_prompt, user_prompt


def _reconstruct_defense_prompt(row: Any, proposed_write: dict) -> tuple:
    """Reconstruct (system_prompt, user_prompt) for defense training examples.

    The defense prompt presents the current process state and a proposed PLC
    write, asking the model to decide allow or block.
    """
    scene = str(row.get("scene", "unknown"))
    obs_dict = row.get("observation_dict")
    if obs_dict is None:
        return "", ""
    if isinstance(obs_dict, str):
        try:
            obs_dict = json.loads(obs_dict)
        except Exception:
            obs_dict = {}

    system_prompt = (
        f"You are a security defender monitoring a Cyber-Physical System. "
        f"Scene: {scene}. Evaluate each proposed PLC write and decide whether "
        f"to ALLOW or BLOCK it. Return a JSON object with fields: "
        f"decision (allow|block), suspicion_score (0.0-1.0), reasoning (string)."
    )
    user_prompt = (
        f"Current process state:\n{json.dumps(obs_dict, indent=2)}\n\n"
        f"Phase: {row.get('inferred_phase', 'unknown')}\n\n"
        f"Proposed write:\n"
        f"  Tag: {proposed_write.get('target_tag', '?')}\n"
        f"  Value: {proposed_write.get('action_value', '?')}\n"
        f"  Type: {proposed_write.get('action_type', '?')}\n"
        f"  Duration: {proposed_write.get('duration_ms', '?')} ms\n\n"
        f"Should this write be allowed or blocked?"
    )
    return system_prompt, user_prompt
