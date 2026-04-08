(* =============================================================================
   CPSForge — Level Control for OpenPLC
   =============================================================================
   Structured Text for OpenPLC Runtime v4 (matiec-compatible).
   
   All located variables use %QW (holding registers) or %QX (coils) so
   both the PLC and the Modbus simulator can read/write them.
   No %IX or %IW (those are read-only via Modbus).
   
   Analog values are scaled x100: physical = raw_int * 0.01
     (e.g., 500 = 5.00 V, 1000 = 10.00 V)
   
   Modbus register mapping:
     %QW0  : FillValve      (INT x100, 0-1000)
     %QW1  : DischargeValve (INT x100, 0-1000)
     %QW2  : SPDisplay      (INT x100, mirror of setpoint)
     %QW3  : PVDisplay      (INT x100, mirror of level)
     %QW10 : LevelMeter     (INT x100, simulator writes)
     %QW11 : FlowMeter      (INT x100, simulator writes)
     %QW12 : SetpointIn     (INT x100, default 500, attackable)
     %QX0.0 : Running       (auto-True when Enable)
     %QX0.1 : Enable        (kill switch, default TRUE)
   ============================================================================= *)

PROGRAM level_control
  VAR
    (* Sensor inputs — written by simulator via Modbus holding registers *)
    LevelMeter_raw  AT %QW10 : INT := 0;
    FlowMeter_raw   AT %QW11 : INT := 0;
    SetpointIn_raw  AT %QW12 : INT := 500;
    
    (* Actuator outputs — computed by this program *)
    FillValve_raw       AT %QW0 : INT := 0;
    DischargeValve_raw  AT %QW1 : INT := 0;
    SPDisplay_raw       AT %QW2 : INT := 0;
    PVDisplay_raw       AT %QW3 : INT := 0;
    
    (* Digital state *)
    Running     AT %QX0.0 : BOOL := FALSE;
    Enable      AT %QX0.1 : BOOL := TRUE;
  END_VAR
  VAR
    (* Internal temps for integer math *)
    err      : INT;
    out_val  : INT;
  END_VAR

  (* Safety gate: if Enable is FALSE, shut everything down *)
  IF NOT Enable THEN
    FillValve_raw := 0;
    DischargeValve_raw := 1000;
    Running := FALSE;
    SPDisplay_raw := 0;
    PVDisplay_raw := LevelMeter_raw;
    RETURN;
  END_IF;

  (* Auto-run when enabled — no physical button logic needed *)
  Running := TRUE;

  (* Update displays *)
  SPDisplay_raw := SetpointIn_raw;
  PVDisplay_raw := LevelMeter_raw;

  (* Proportional control — all in INT x100 space *)
  err := SetpointIn_raw - LevelMeter_raw;

  IF err > 0 THEN
    out_val := err;
    IF out_val > 1000 THEN out_val := 1000; END_IF;
    FillValve_raw := out_val;
    DischargeValve_raw := 0;
  ELSE
    FillValve_raw := 0;
    out_val := -err;
    IF out_val > 1000 THEN out_val := 1000; END_IF;
    DischargeValve_raw := out_val;
  END_IF;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#50ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Main : level_control;
  END_RESOURCE
END_CONFIGURATION
