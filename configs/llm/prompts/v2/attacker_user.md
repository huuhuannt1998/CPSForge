## Attacker Objective

{attacker_objective}

---

## Current Plant State  (step {step_id})

```json
{scene_state}
```

---

## Prior Actions This Session

```json
{prior_actions}
```

---

{notes}

---

## Your Task

Generate up to {max_actions} attack action(s) targeting the plant state shown above.

Work through the reasoning chain from the system instructions:
  1. What is the current process state and which variables are near limits?
  2. Which tag manipulation causes the highest impact while remaining stealthy?
  3. Is this consistent with prior actions (amplify the existing deviation)?

Then output ONLY the JSON array — nothing else.
Start with '[' and end with ']'.
Do NOT wrap in markdown fences or add any explanatory text.
