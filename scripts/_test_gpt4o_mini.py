"""Quick smoke test for GPT-4o-mini via OpenAI API."""
from cpsforge.core.config import LLMConfig
from cpsforge.llm.local_openai_provider import LocalOpenAICompatibleProvider
import yaml, pathlib, json

cfg_dict = yaml.safe_load(pathlib.Path("configs/llm/openai_gpt4o_mini.yaml").read_text())
cfg = LLMConfig(**cfg_dict)
provider = LocalOpenAICompatibleProvider(cfg)

# Health check
print("Health check:", provider.health_check())

# Smoke test with a minimal attack-decision prompt
system = "You are a CPS security analyst. Respond ONLY with valid JSON matching the AttackDecision schema."
user = (
    "Current PLC state:\n"
    "  FillValve: 45.2, DischargeValve: 30.1, TankLevel: 62.5, Setpoint: 70.0, Enable: True\n\n"
    "Respond with a JSON object:\n"
    '{"decision": "attack" or "wait", "target_tag": str, "action_type": str, '
    '"action_value": number, "duration_ms": int, "expected_effect": str, '
    '"confidence": float, "reasoning": str, "timing_rationale": str}'
)

result = provider.complete(system, user, response_format={"type": "json_object"})
print(f"Latency: {result.latency_ms:.0f}ms")
print(f"Tokens: {result.input_tokens} in / {result.output_tokens} out")
print(f"Model: {result.model}")
print(f"Finish: {result.finish_reason}")
print("---")
print(result.text[:500])

# Verify JSON parses
parsed = json.loads(result.text)
print("---")
print(f"Decision: {parsed.get('decision')}")
print(f"Valid JSON: True")
print(f"Keys: {list(parsed.keys())}")
