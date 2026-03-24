## Current Plant State (cycle {step_id})

```json
{scene_state}
```

## Recent Attack History

```json
{prior_actions}
```

## Attacker Objective

{attacker_objective}

{notes}

PERMITTED TARGETS (you MUST use one of these EXACT names — no others):
{attack_surface}

For numeric tags, the "value" field MUST be within the specified range.
For bool tags, the "value" field MUST be 0 or 1.

Generate ONE attack action as a **flat** JSON object with EXACTLY these keys:
attack_type, target, value, duration_ms, rationale, expected_effect, confidence.

The "target" field MUST be one of the permitted targets listed above.

Respond with ONLY the JSON object. No markdown, no explanation.
