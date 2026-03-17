## Current Plant State (cycle {step_id})

```json
{scene_state}
```

## Detector Alerts

```json
{detector_alerts}
```

## Recent Detection History

```json
{prior_detections}
```

{notes}

Return a **flat** JSON object with EXACTLY these keys:
summary, confidence, root_cause, corrective_action.

Example (do NOT copy -- adapt to alerts):
{{"summary":"anomaly detected","confidence":0.8,"root_cause":"...","corrective_action":{{"target":"fill_valve","value":50.0,"duration_ms":3000,"rationale":"restore normal"}}}}

Set corrective_action to null if no correction is needed.
Respond with ONLY the JSON. No markdown, no explanation.
