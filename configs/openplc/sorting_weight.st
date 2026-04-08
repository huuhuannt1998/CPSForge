(* =============================================================================
   CPSForge — Sorting by Weight (OpenPLC Structured Text)
   =============================================================================
   IEC 61131-3 Structured Text for OpenPLC Runtime v4 (matiec-compatible).

   3-way weight sorter: weigh each box on a scale, then route:
     weight < LightThresh (200 = 2.0 kg) -> LEFT
     weight >= HeavyThresh (500 = 5.0 kg) -> RIGHT
     otherwise -> FORWARD

   ALL located variables use %QW (holding registers) or %QX (coils) so
   both PLC and Modbus simulator can read/write them.
   No %IX or %IW (read-only via Modbus).

   Modbus mapping:
     Actuator outputs (Holding Registers):
       HR0-%QW0  EntryConveyor     HR4-%QW4  SendRight
       HR1-%QW1  LoadScale         HR5-%QW5  RightConveyor
       HR2-%QW2  SendLeft          HR6-%QW6  SendForward
       HR3-%QW3  LeftConveyor      HR7-%QW7  FrontConveyor

     Thresholds/state (Holding Registers, INT x100):
       HR10-%QW10  LightThresh     HR12-%QW12  MeasuredWeight
       HR11-%QW11  HeavyThresh     HR13-%QW13  Weight_raw (sim writes)

     Counters (Holding Registers):
       HR20-%QW20  LeftCount       HR22-%QW22  RightCount
       HR21-%QW21  ForwardCount    HR23-%QW23  iState

     Mode/state (Coils):
       COIL0-%QX0.0  Enable

     Sensor inputs from simulator (Coils):
       COIL8-%QX1.0   AtScaleEntry    COIL13-%QX1.5  AtForwardEntry
       COIL9-%QX1.1   AtScale         COIL14-%QX1.6  AtExitFront
       COIL10-%QX1.2  AtScaleExit     COIL15-%QX1.7  AtRightEntry
       COIL11-%QX1.3  AtLeftEntry     COIL16-%QX2.0  AtExitRight
       COIL12-%QX1.4  AtExitLeft
   ============================================================================= *)

PROGRAM SortingWeight
  VAR
    (* Actuator outputs — Holding Registers *)
    EntryConveyor   AT %QW0   : INT := 0;
    LoadScale       AT %QW1   : INT := 0;
    SendLeft        AT %QW2   : INT := 0;
    LeftConveyor    AT %QW3   : INT := 0;
    SendRight       AT %QW4   : INT := 0;
    RightConveyor   AT %QW5   : INT := 0;
    SendForward     AT %QW6   : INT := 0;
    FrontConveyor   AT %QW7   : INT := 0;

    (* Thresholds — Holding Registers (INT x100) *)
    LightThresh     AT %QW10  : INT := 200;
    HeavyThresh     AT %QW11  : INT := 500;
    MeasuredWeight  AT %QW12  : INT := 0;

    (* Weight sensor — simulator writes here via Modbus HR13 *)
    Weight_raw      AT %QW13  : INT := 0;

    (* Counters + state — Holding Registers *)
    LeftCount       AT %QW20  : INT := 0;
    ForwardCount    AT %QW21  : INT := 0;
    RightCount      AT %QW22  : INT := 0;
    iState          AT %QW23  : INT := 0;

    (* Mode — Coils *)
    Enable          AT %QX0.0 : BOOL := TRUE;

    (* Sensor inputs from simulator — Coils (writable via Modbus) *)
    AtScaleEntry    AT %QX1.0 : BOOL := FALSE;
    AtScale         AT %QX1.1 : BOOL := FALSE;
    AtScaleExit     AT %QX1.2 : BOOL := FALSE;
    AtLeftEntry     AT %QX1.3 : BOOL := FALSE;
    AtExitLeft      AT %QX1.4 : BOOL := FALSE;
    AtForwardEntry  AT %QX1.5 : BOOL := FALSE;
    AtExitFront     AT %QX1.6 : BOOL := FALSE;
    AtRightEntry    AT %QX1.7 : BOOL := FALSE;
    AtExitRight     AT %QX2.0 : BOOL := FALSE;
  END_VAR

  (* Exit conveyors always run *)
  LeftConveyor  := 1;
  FrontConveyor := 1;
  RightConveyor := 1;

  (* Default thresholds if not set *)
  IF LightThresh < 10 THEN LightThresh := 200; END_IF;
  IF HeavyThresh < 10 THEN HeavyThresh := 500; END_IF;

  IF NOT Enable THEN
    EntryConveyor := 0;
    LoadScale     := 0;
    SendLeft      := 0;
    SendRight     := 0;
    SendForward   := 0;
    iState        := 0;
  ELSE
    CASE iState OF
      0: (* Idle — feed box onto scale *)
        EntryConveyor := 1;
        LoadScale     := 1;
        SendLeft      := 0;
        SendRight     := 0;
        SendForward   := 0;
        IF AtScale THEN
          EntryConveyor := 0;
          LoadScale     := 0;
          MeasuredWeight := Weight_raw;
          iState := 1;
        END_IF;

      1: (* Weighed — decide direction *)
        EntryConveyor := 0;
        LoadScale     := 0;
        IF MeasuredWeight < LightThresh THEN
          SendLeft := 1;
          iState := 2;
        ELSIF MeasuredWeight >= HeavyThresh THEN
          SendRight := 1;
          iState := 4;
        ELSE
          SendForward := 1;
          iState := 6;
        END_IF;

      2: (* Sending left *)
        SendLeft  := 1;
        LoadScale := 1;
        IF NOT AtScale AND NOT AtScaleExit THEN
          SendLeft    := 0;
          LoadScale   := 0;
          LeftCount   := LeftCount + 1;
          iState      := 0;
        END_IF;

      4: (* Sending right *)
        SendRight := 1;
        LoadScale := 1;
        IF NOT AtScale AND NOT AtScaleExit THEN
          SendRight   := 0;
          LoadScale   := 0;
          RightCount  := RightCount + 1;
          iState      := 0;
        END_IF;

      6: (* Sending forward *)
        SendForward := 1;
        LoadScale   := 1;
        IF NOT AtScale AND NOT AtScaleExit THEN
          SendForward  := 0;
          LoadScale    := 0;
          ForwardCount := ForwardCount + 1;
          iState       := 0;
        END_IF;

    ELSE
      iState := 0;
    END_CASE;
  END_IF;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#50ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Main : SortingWeight;
  END_RESOURCE
END_CONFIGURATION
