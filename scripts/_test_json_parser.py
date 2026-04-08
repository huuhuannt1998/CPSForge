"""Quick test of _parse_json_response with multi-line code fields."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpsforge.attacker.logic_analyzer import _parse_json_response

# Simulate LLM output with literal newlines in JSON string fields
test = '{\n  "decision": "modify",\n  "modification_type": "comparison_inversion",\n  "original_code": "IF error > 0.0 THEN\n    output := error * 1.0;\n    FillValve := output;",\n  "modified_code": "IF error < 0.0 THEN\n    output := error * 1.0;\n    FillValve := output;",\n  "expected_effect": "Inverts control",\n  "reasoning": "Flip comparison"\n}'

result = _parse_json_response(test)
print("PARSED OK")
print(f"original_code: {result['original_code']!r}")
print(f"Lines in original_code: {result['original_code'].count(chr(10)) + 1}")
print(f"modification_type: {result['modification_type']}")
