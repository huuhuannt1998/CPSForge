(* =============================================================================
   CPSForge — Sorting by Height Basic (OpenPLC Structured Text)
   =============================================================================
   IEC 61131-3 Structured Text for OpenPLC Runtime v4 (matiec-compatible).

   2-way height sorter:
     Short item (low sensor only) -> Transfer LEFT
     Tall  item (high sensor)     -> Transfer RIGHT

   State machine:
     0=Feed, 1=Load, 2=Transfer, 3=Clear, 4=Finish

   ALL located variables use %QW (holding registers) or %QX (coils) so
   both PLC and Modbus simulator can read/write them.
   No %IX or %IW (read-only via Modbus).

   Modbus mapping:
     Actuator outputs (Holding Registers):
       HR0-%QW0   ConveyorEntry   HR4-%QW4   TransfRight
       HR1-%QW1   LoadAct         HR5-%QW5   ConveyorLeft
       HR2-%QW2   UnloadAct       HR6-%QW6   ConveyorRight
       HR3-%QW3   TransfLeft

     Counters/state (Holding Registers):
       HR10-%QW10  CounterOut      HR11-%QW11  iState

     Mode (Coils):
       COIL0-%QX0.0  Enable

     Sensor inputs from simulator (Coils):
       COIL8-%QX1.0   HighSensor      COIL12-%QX1.4  AtLeftEntry
       COIL9-%QX1.1   LowSensor       COIL13-%QX1.5  AtLeftExit
       COIL10-%QX1.2  PalletSensor    COIL14-%QX1.6  AtRightEntry
       COIL11-%QX1.3  Loaded          COIL15-%QX1.7  AtRightExit
   ============================================================================= *)

PROGRAM SortingHeight
  VAR
    (* Actuator outputs — Holding Registers *)
    ConveyorEntry   AT %QW0   : INT := 0;
    LoadAct         AT %QW1   : INT := 0;
    UnloadAct       AT %QW2   : INT := 0;
    TransfLeft      AT %QW3   : INT := 0;
    TransfRight     AT %QW4   : INT := 0;
    ConveyorLeft    AT %QW5   : INT := 0;
    ConveyorRight   AT %QW6   : INT := 0;

    (* Counters + state — Holding Registers *)
    CounterOut      AT %QW10  : INT := 0;
    iState          AT %QW11  : INT := 0;

    (* Mode — Coils *)
    Enable          AT %QX0.0 : BOOL := TRUE;

    (* Sensor inputs from simulator — Coils (writable via Modbus) *)
    HighSensor      AT %QX1.0 : BOOL := FALSE;
    LowSensor       AT %QX1.1 : BOOL := FALSE;
    PalletSensor    AT %QX1.2 : BOOL := FALSE;
    Loaded          AT %QX1.3 : BOOL := FALSE;
    AtLeftEntry     AT %QX1.4 : BOOL := FALSE;
    AtLeftExit      AT %QX1.5 : BOOL := FALSE;
    AtRightEntry    AT %QX1.6 : BOOL := FALSE;
    AtRightExit     AT %QX1.7 : BOOL := FALSE;
  END_VAR
  VAR
    (* Internal — non-located *)
    IsTall          : BOOL := FALSE;
    DwellTimer      : INT  := 0;
    ItemCount       : INT  := 0;
  END_VAR

  (* ── Safety gate ── *)
  IF NOT Enable THEN
    ConveyorEntry := 0; LoadAct := 0; UnloadAct := 0;
    TransfLeft := 0; TransfRight := 0;
    ConveyorLeft := 0; ConveyorRight := 0;
    RETURN;
  END_IF;

  (* Exit conveyors always ON *)
  ConveyorLeft  := 1;
  ConveyorRight := 1;

  (* ── State machine ── *)
  CASE iState OF
    0: (* FEED: entry conveyor on, detect height *)
      ConveyorEntry := 1;
      LoadAct := 0; UnloadAct := 0;
      TransfLeft := 0; TransfRight := 0;

      IF HighSensor THEN IsTall := TRUE;
      ELSIF LowSensor THEN IsTall := FALSE;
      END_IF;

      IF PalletSensor THEN
        DwellTimer := 0;
        iState := 1;
      END_IF;

    1: (* LOAD: run entry conveyor until loaded *)
      IF Loaded THEN ConveyorEntry := 0;
      ELSE ConveyorEntry := 1;
      END_IF;
      LoadAct := 1;
      UnloadAct := 0;
      TransfLeft := 0; TransfRight := 0;

      IF HighSensor THEN IsTall := TRUE;
      ELSIF LowSensor THEN IsTall := FALSE;
      END_IF;

      DwellTimer := DwellTimer + 1;

      IF Loaded THEN
        DwellTimer := 0;
        iState := 2;
      ELSIF DwellTimer > 5000 THEN
        ConveyorEntry := 0;
        DwellTimer := 0;
        iState := 2;
      END_IF;

    2: (* TRANSFER: short->LEFT, tall->RIGHT *)
      ConveyorEntry := 0;
      LoadAct := 1;  (* Keep chains raised *)

      IF IsTall THEN
        TransfRight := 1; TransfLeft := 0;
      ELSE
        TransfLeft := 1; TransfRight := 0;
      END_IF;

      DwellTimer := DwellTimer + 1;
      IF DwellTimer > 3000 THEN
        DwellTimer := 0;
        iState := 3;
      END_IF;

    3: (* CLEAR: wait for item to leave *)
      ConveyorEntry := 0;
      LoadAct := 0;
      UnloadAct := 1;
      TransfLeft := 0; TransfRight := 0;

      DwellTimer := DwellTimer + 1;
      IF DwellTimer > 2000 THEN
        DwellTimer := 0;
        iState := 4;
      END_IF;

    4: (* FINISH: increment counter, return to feed *)
      UnloadAct := 0;
      ItemCount := ItemCount + 1;
      CounterOut := ItemCount;
      iState := 0;

  ELSE
    iState := 0;
  END_CASE;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#50ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Main : SortingHeight;
  END_RESOURCE
END_CONFIGURATION
