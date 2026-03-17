"""Test phi-3 with the exact agent attacker prompt."""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpsforge.core.config import LLMConfig
from cpsforge.core.models import PlantSnapshot, AttackContext, DefenseContext, SafetyContext
from cpsforge.llm.local_openai_provider import LocalOpenAICompatibleProvider
from cpsforge.llm.prompt_builder import PromptBuilder
from cpsforge.core.config import ConfigLoader
from cpsforge.scenes.factory import load_scene

loader = ConfigLoader()
scene = load_scene("level_control", loader)
pb = PromptBuilder()

class W: pass
w = W()
w.profile = scene.profile

sys_prompt = pb.build_attacker_agent_system_prompt(w)

snap = PlantSnapshot(
    scene_name="level_control", run_id="test", step_id=5,
    sensors={"level_in": 50.0, "level_out": 30.0, "flow_in": 5.0, "flow_out": 3.0, "water_level": 45.0},
    actuators={"fill_valve": 50.0, "discharge_valve": 30.0},
    controller_state={"auto_mode": True, "run_mode": True},
    alarms={}, setpoints={"setpoint_in": 50.0, "setpoint_out": 30.0},
    attack_context=AttackContext(), defense_context=DefenseContext(),
    safety_context=SafetyContext(),
)

usr_prompt = pb.build_attacker_agent_user_prompt(
    snapshot=snap, prior_actions=[], attacker_objective="maximize physical deviation while remaining plausible",
)

cfg = LLMConfig(
    provider="local_openai_compatible", model="phi-3-mini-4k-instruct",
    base_url="http://127.0.0.1:1234/v1", max_tokens=256, temperature=0.2, timeout_s=120.0,
)
p = LocalOpenAICompatibleProvider(cfg)

for i in range(3):
    result = p.complete(sys_prompt, usr_prompt)
    print(f"\n--- Attempt {i+1} ({result.input_tokens} in / {result.output_tokens} out) ---")
    print(result.text)
