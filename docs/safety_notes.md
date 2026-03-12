# Safety Notes

CPSForge controls a real PLC connected to physical hardware. Safety is enforced at multiple levels.

---

## 1. Dry-Run Mode (Default)

By default, **no writes are sent to the PLC**. The system simulates the full pipeline — attack generation, shield evaluation, detector scoring — without touching hardware.

```bash
# Dry-run (default, no --live-writes flag)
cpsforge run attack --scene tank_control --attacker scripted
```

Dry-run mode still:
- Reads live PLC tags (if connected)
- Logs trace data
- Records shield decisions
- Runs detectors

It does **not**:
- Write any value to the PLC
- Modify actuator states
- Change setpoints

---

## 2. Enabling Live Writes

Live writes require **both** conditions:

1. The `--live-writes` CLI flag:
   ```bash
   cpsforge run attack --scene tank_control --attacker scripted --live-writes
   ```

2. The environment variable `CPSFORGE_LIVE_WRITES=true` in `.env` or shell.

If either is missing, writes are blocked. This two-gate design prevents accidental live operation.

---

## 3. Shield Enforcement

Every proposed write passes through the shield before reaching the PLC. The shield enforces:

| Rule Type | What It Checks |
|-----------|---------------|
| **Whitelist** | Only tags in `writable_tags` can be written |
| **Range** | Values must be within `min_value`–`max_value` |
| **Duration** | Overrides expire after `max_duration_ms` |
| **Cooldown** | Minimum gap between writes to the same tag |
| **Mutual exclusion** | Forbidden simultaneous tag overrides |
| **Mode gate** | Writes only allowed in a specific PLC mode |
| **Invariant** | Boolean conditions over plant state that must hold |
| **Interlock** | Conditional write permissions |

A rejected write returns a `ShieldDecision` with `approved=False` and the list of `violated_rules`. Rejected writes are **never** sent to the PLC.

---

## 4. Deadman Timer

The shield runs a deadman timer. If the orchestrator fails to send a heartbeat within the configured interval, all active overrides are rolled back and the plant is returned to its last known safe state.

---

## 5. Rollback Plans

Every approved write includes a `rollback_plan` that specifies how to undo the action. If an experiment is aborted (Ctrl+C, error, deadman timeout), rollback plans execute automatically.

---

## 6. No Raw PLC Writes from LLM

The LLM attacker outputs structured `AttackAction` objects. These are:
1. Validated against the scene's attack surface
2. Compiled into concrete tag writes by the action compiler
3. Checked by the shield before execution

The LLM never produces raw PLC addresses or byte-level writes. This is enforced by:
- The attack action schema (targets are tag names, not addresses)
- The action compiler (translates tag names → addresses)
- The shield (validates every write)

---

## 7. Audit Trail

Every action is logged:

| Artifact | Contents |
|----------|----------|
| `trace.parquet` | Full plant snapshot timeline |
| `attacks.json` | All proposed attack actions |
| `shield_events.json` | All shield decisions (approved + rejected) |
| `detections.json` | All detector events |
| `metadata.json` | Run configuration and timestamps |

No action can bypass logging. The trace is the single source of truth for experiment analysis.

---

## 8. Operational Procedures

### Before a Live Experiment

1. **Verify PLC connectivity**: `cpsforge plc probe`
2. **Validate scene config**: `cpsforge scene validate --scene <name>`
3. **Run dry-run first**: `cpsforge run attack --scene <name> --attacker scripted`
4. **Review shield rules** in the scene YAML
5. **Ensure Factory I/O is in a known state** (reset scene)
6. **Confirm emergency stop is accessible** on the Factory I/O interface

### During a Live Experiment

- Monitor the terminal output (Rich live display shows current state)
- Watch Factory I/O for unexpected behavior
- Press **Ctrl+C** to abort — rollback plans execute automatically

### After a Live Experiment

1. Verify plant returned to safe state
2. Review `shield_events.json` for any rejected actions
3. Review `metrics.json` for experiment outcomes
4. Archive the run folder before the next experiment

---

## 9. Known Limitations

- The shield operates on tag-level rules. It does not model full plant dynamics.
- Rollback assumes the PLC accepts the rollback write. Network failure during rollback is not handled.
- The deadman timer relies on the Python process remaining alive. An OS-level crash bypasses it.
- Factory I/O's built-in safety features (if any) are independent of CPSForge's shield.

---

## 10. Emergency Procedures

If the plant enters an unsafe state:

1. **Stop Factory I/O** via the Factory I/O interface (pause/stop button)
2. **Disconnect the PLC** from the network (pull Ethernet cable)
3. **Kill the CPSForge process** (`Ctrl+C` or terminate)
4. **Review logs** in the run folder to determine root cause
5. **Reset the PLC** to a known program state via TIA Portal if needed
