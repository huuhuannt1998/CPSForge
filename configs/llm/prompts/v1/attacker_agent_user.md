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

Generate ONE attack action as a **flat** JSON object with EXACTLY these keys:
attack_type, target, value, duration_ms, rationale, expected_effect, confidence.

Example (do NOT copy values -- adapt to the current state):
{{"attack_type":"sensor_spoof","target":"water_level","value":95.0,"duration_ms":5000,"rationale":"...","expected_effect":"...","confidence":0.8}}

Respond with ONLY the JSON object. No markdown, no explanation.
