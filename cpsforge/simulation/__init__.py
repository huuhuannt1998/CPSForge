"""
cpsforge.simulation
====================
Lightweight Python process simulators for OpenPLC integration.

Each simulator models the physical process that Factory I/O would provide,
but communicates directly with OpenPLC via Modbus TCP.  This enables
fully automated experiments without commercial software.

The simulators update at a configurable tick rate, reading actuator outputs
from the PLC (holding registers) and writing sensor inputs back to the PLC
(input registers), closing the control loop.

Simulator models:
  - TankSimulator: Level Control (Scene 12 equivalent)
  - WeightSorterSimulator: Sorting by Weight (Scene 20 equivalent)
  - HeightSorterSimulator: Sorting by Height (Scene 19 equivalent)
"""

from __future__ import annotations

import logging
import math
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from threading import Event, Thread
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base simulator
# ---------------------------------------------------------------------------


class ProcessSimulator(ABC):
    """
    Base class for all process simulators.

    A simulator runs in a background thread, reading PLC outputs (actuators)
    and writing PLC inputs (sensors) via a Modbus client at each tick.
    """

    def __init__(self, modbus_client, tick_interval_s: float = 0.1) -> None:
        self._modbus = modbus_client
        self._tick_interval = tick_interval_s
        self._stop_event = Event()
        self._thread: Optional[Thread] = None
        self._step: int = 0

    def start(self) -> None:
        """Start the simulator in a background thread."""
        self._stop_event.clear()
        self._thread = Thread(target=self._run_loop, daemon=True,
                              name=f"{self.__class__.__name__}")
        self._thread.start()
        logger.info("%s started (tick=%.3fs)", self.__class__.__name__,
                    self._tick_interval)

    def stop(self) -> None:
        """Stop the simulator."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        logger.info("%s stopped after %d steps.", self.__class__.__name__,
                    self._step)

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.tick()
                self._step += 1
            except Exception as exc:
                logger.error("%s tick error: %s", self.__class__.__name__, exc)
            self._stop_event.wait(self._tick_interval)

    @abstractmethod
    def tick(self) -> None:
        """Execute one simulation step."""

    @abstractmethod
    def reset(self) -> None:
        """Reset simulator state to initial conditions."""

    def _read_register(self, address: int, count: int = 1) -> Optional[list]:
        """Read holding registers from PLC (actuator outputs)."""
        try:
            r = self._modbus._client.read_holding_registers(
                address, count=count, device_id=self._modbus._config.unit_id)
            return r.registers if not r.isError() else None
        except Exception:
            return None

    def _write_register(self, address: int, values: list) -> bool:
        """Write input registers to PLC (sensor inputs)."""
        try:
            r = self._modbus._client.write_registers(
                address, values, device_id=self._modbus._config.unit_id)
            return not r.isError()
        except Exception:
            return False

    def _read_coil(self, address: int) -> Optional[bool]:
        """Read a single coil from PLC (digital actuator output)."""
        try:
            r = self._modbus._client.read_coils(
                address, count=1, device_id=self._modbus._config.unit_id)
            return r.bits[0] if not r.isError() else None
        except Exception:
            return None

    def _write_discrete(self, address: int, value: bool) -> bool:
        """Write a discrete input to PLC (digital sensor input)."""
        try:
            # OpenPLC: use write_coil on the input-mapped coil range
            # or use the debug/force interface. For simulation, we write
            # to input registers as single-bit packed values.
            r = self._modbus._client.write_coil(
                address, value, device_id=self._modbus._config.unit_id)
            return not r.isError()
        except Exception:
            return False

    @staticmethod
    def _float_to_regs(value: float) -> list:
        """Convert IEEE 754 float to two 16-bit Modbus registers (big-endian)."""
        import struct
        raw = struct.pack(">f", value)
        hi, lo = struct.unpack(">HH", raw)
        return [hi, lo]

    @staticmethod
    def _regs_to_float(regs: list) -> float:
        """Convert two 16-bit Modbus registers to IEEE 754 float (big-endian)."""
        import struct
        raw = struct.pack(">HH", regs[0], regs[1])
        return struct.unpack(">f", raw)[0]


# ---------------------------------------------------------------------------
# Tank Level Control Simulator (Scene 12 equivalent)
# ---------------------------------------------------------------------------


@dataclass
class TankState:
    """Physical state of the tank level control process."""
    level: float = 0.0           # Tank level (0.0 - 10.0 volts)
    flow_rate: float = 0.0      # Current flow rate (0.0 - 10.0 volts)
    fill_valve: float = 0.0     # Fill valve opening (0.0 - 10.0, from PLC)
    discharge_valve: float = 0.0  # Discharge valve opening (0.0 - 10.0, from PLC)
    setpoint: float = 5.0       # Operator setpoint (0.0 - 10.0)
    running: bool = False


class TankSimulator(ProcessSimulator):
    """
    Simulates a tank with fill and discharge valves.

    Physics model:
      - Fill rate proportional to fill_valve opening
      - Discharge rate proportional to discharge_valve opening and sqrt(level)
      - Level changes as integral of (fill - discharge) over dt
      - Small noise added to level sensor reading

    Modbus register mapping (INT x100, mirrors OpenPLC ST program):
      Reading FROM PLC (holding registers — PLC outputs):
        HR0  → fill_valve (INT x100: 0-1000 → 0.0-10.0V)
        HR1  → discharge_valve (INT x100)
        COIL0 → running (PLC start command)

      Writing TO PLC (holding registers — sensor feedback):
        HR10 → level_meter (INT x100)
        HR11 → flow_meter (INT x100)
        HR12 → setpoint_in (INT x100)
    """

    # Modbus addresses for PLC actuator outputs (single INT registers)
    ADDR_FILL_VALVE = 0       # HR0
    ADDR_DISCHARGE_VALVE = 1  # HR1
    ADDR_RUNNING = 0          # COIL0

    # Modbus addresses for sensor feedback to PLC
    ADDR_LEVEL_METER = 10     # HR10
    ADDR_FLOW_METER = 11      # HR11
    ADDR_SETPOINT_IN = 12     # HR12

    # Scale factor: physical = raw * SCALE
    SCALE = 0.01
    INV_SCALE = 100  # raw = physical * INV_SCALE

    # Physics parameters
    FILL_RATE_MAX = 2.0       # V/s at full valve opening
    DISCHARGE_RATE_MAX = 1.5  # V/s at full valve opening and full tank
    TANK_MAX = 10.0           # Maximum level (volts)
    NOISE_STDDEV = 0.02       # Sensor noise standard deviation

    def __init__(self, modbus_client, tick_interval_s: float = 0.1) -> None:
        super().__init__(modbus_client, tick_interval_s)
        self.state = TankState()

    def reset(self) -> None:
        self.state = TankState()

    def tick(self) -> None:
        dt = self._tick_interval

        # Read actuator outputs from PLC (INT x100 → float)
        fill_regs = self._read_register(self.ADDR_FILL_VALVE, 1)
        if fill_regs:
            self.state.fill_valve = max(0.0, min(10.0, fill_regs[0] * self.SCALE))

        disc_regs = self._read_register(self.ADDR_DISCHARGE_VALVE, 1)
        if disc_regs:
            self.state.discharge_valve = max(0.0, min(10.0, disc_regs[0] * self.SCALE))

        running = self._read_coil(self.ADDR_RUNNING)
        if running is not None:
            self.state.running = running

        # Physics: compute level change
        fill_rate = (self.state.fill_valve / 10.0) * self.FILL_RATE_MAX
        # Discharge rate depends on current level (gravity-driven)
        level_factor = math.sqrt(max(0.0, self.state.level / self.TANK_MAX))
        discharge_rate = (self.state.discharge_valve / 10.0) * self.DISCHARGE_RATE_MAX * level_factor

        net_flow = fill_rate - discharge_rate
        self.state.flow_rate = abs(net_flow)

        self.state.level += net_flow * dt
        self.state.level = max(0.0, min(self.TANK_MAX, self.state.level))

        # Write sensor readings back to PLC (float → INT x100, with noise)
        noisy_level = self.state.level + random.gauss(0, self.NOISE_STDDEV)
        noisy_level = max(0.0, min(self.TANK_MAX, noisy_level))

        self._write_register(self.ADDR_LEVEL_METER,
                             [max(0, min(1000, round(noisy_level * self.INV_SCALE)))])
        self._write_register(self.ADDR_FLOW_METER,
                             [max(0, min(1000, round(self.state.flow_rate * self.INV_SCALE)))])
        self._write_register(self.ADDR_SETPOINT_IN,
                             [max(0, min(1000, round(self.state.setpoint * self.INV_SCALE)))])


# ---------------------------------------------------------------------------
# Sorting by Weight Simulator (Scene 20 equivalent)
# ---------------------------------------------------------------------------


@dataclass
class WeightSorterState:
    """Physical state of the weight sorting process."""
    # Conveyor positions (0.0 = start, 1.0 = end of segment)
    item_position: float = -1.0      # -1 = no item on conveyor
    item_weight: float = 0.0         # Weight of current item
    sorted_left: int = 0
    sorted_forward: int = 0
    sorted_right: int = 0
    state_machine: int = 0           # 0=idle, 1=loading, 2=weighing, 3=sorting


class WeightSorterSimulator(ProcessSimulator):
    """
    Simulates a 3-way weight sorter.

    Items arrive randomly, are weighed on a scale, then sorted left
    (light), forward (medium), or right (heavy) based on weight thresholds.

    Modbus register mapping (matches sorting_weight.st):
      Reading FROM PLC (holding registers — actuator commands):
        HR0  → entry_conveyor (0/1)
        HR1  → load_scale     (0/1)
        HR2  → send_left      (0/1)
        HR4  → send_right     (0/1)
        HR6  → send_forward   (0/1)

      Writing TO PLC:
        HR13     → weight_raw (INT x100, scale reading)
        COIL8    → at_scale_entry
        COIL9    → at_scale
        COIL10   → at_scale_exit
        COIL11   → at_left_entry
        COIL12   → at_exit_left
        COIL13   → at_forward_entry
        COIL14   → at_exit_front
        COIL15   → at_right_entry
        COIL16   → at_exit_right
    """

    # Weight distribution for random items
    WEIGHT_LIGHT = (0.5, 1.5)    # kg range for "light"
    WEIGHT_MEDIUM = (2.0, 3.5)   # kg range for "medium"
    WEIGHT_HEAVY = (4.0, 6.0)    # kg range for "heavy"

    # Conveyor speed (position units per second)
    CONVEYOR_SPEED = 0.5

    # Item spawn interval (seconds between items)
    SPAWN_INTERVAL = (3.0, 6.0)

    # INT x100 scale factor
    SCALE = 100

    def __init__(self, modbus_client, tick_interval_s: float = 0.1) -> None:
        super().__init__(modbus_client, tick_interval_s)
        self.state = WeightSorterState()
        self._spawn_timer = 0.0
        self._next_spawn = random.uniform(*self.SPAWN_INTERVAL)

    def reset(self) -> None:
        self.state = WeightSorterState()
        self._spawn_timer = 0.0
        self._next_spawn = random.uniform(*self.SPAWN_INTERVAL)

    def tick(self) -> None:
        dt = self._tick_interval

        # Read actuator commands from PLC (holding registers, 0/1 as INT)
        entry_regs = self._read_register(0, 1)      # HR0
        entry_on = entry_regs and entry_regs[0] != 0
        send_left_regs = self._read_register(2, 1)   # HR2
        send_left = send_left_regs and send_left_regs[0] != 0
        send_right_regs = self._read_register(4, 1)  # HR4
        send_right = send_right_regs and send_right_regs[0] != 0
        send_fwd_regs = self._read_register(6, 1)    # HR6
        send_forward = send_fwd_regs and send_fwd_regs[0] != 0

        # Spawn items periodically
        self._spawn_timer += dt
        if self._spawn_timer >= self._next_spawn and self.state.item_position < 0:
            # Spawn a new item with random weight category
            cat = random.choice(["light", "medium", "heavy"])
            if cat == "light":
                self.state.item_weight = random.uniform(*self.WEIGHT_LIGHT)
            elif cat == "medium":
                self.state.item_weight = random.uniform(*self.WEIGHT_MEDIUM)
            else:
                self.state.item_weight = random.uniform(*self.WEIGHT_HEAVY)
            self.state.item_position = 0.0
            self.state.state_machine = 1  # loading
            self._spawn_timer = 0.0
            self._next_spawn = random.uniform(*self.SPAWN_INTERVAL)

        # Move item along conveyor if entry conveyor is on
        if self.state.item_position >= 0 and entry_on:
            self.state.item_position += self.CONVEYOR_SPEED * dt

        # State machine for sorting
        at_scale = 0.3 < self.state.item_position < 0.5
        at_scale_exit = self.state.item_position >= 0.7

        # Write sensor feedback (coils 8-16, weight as HR13 INT x100)
        self._write_discrete(9, at_scale)       # COIL9 = at_scale
        self._write_discrete(10, at_scale_exit)  # COIL10 = at_scale_exit

        if at_scale:
            weight_int = max(0, min(1000, round(self.state.item_weight * self.SCALE)))
            self._write_register(13, [weight_int])  # HR13 = weight_raw
            self.state.state_machine = 2  # weighing

        # Sorting decision (applied by PLC, we just track position)
        if at_scale_exit and self.state.state_machine == 2:
            self.state.state_machine = 3  # sorted
            if send_left:
                self.state.sorted_left += 1
            elif send_right:
                self.state.sorted_right += 1
            elif send_forward:
                self.state.sorted_forward += 1
            # Item exits
            self.state.item_position = -1.0
            self.state.state_machine = 0


# ---------------------------------------------------------------------------
# Sorting by Height Simulator (Scene 19 equivalent)
# ---------------------------------------------------------------------------


@dataclass
class HeightSorterState:
    """Physical state of the height sorting process."""
    item_position: float = -1.0
    item_is_tall: bool = False
    sorted_left: int = 0       # Short items
    sorted_right: int = 0      # Tall items
    item_count: int = 0


class HeightSorterSimulator(ProcessSimulator):
    """
    Simulates a 2-way height sorter.

    Items arrive, pass under a height sensor, and are sorted:
    short items go left, tall items go right.

    Modbus register mapping (matches sorting_height.st):
      Reading FROM PLC (holding registers — actuator commands):
        HR0  → conveyor_entry (0/1)
        HR3  → transf_left    (0/1)
        HR4  → transf_right   (0/1)

      Writing TO PLC (coils — sensor feedback):
        COIL8  → high_sensor
        COIL9  → low_sensor
        COIL10 → pallet_sensor
        COIL11 → loaded
        COIL12 → at_left_entry
        COIL13 → at_left_exit
        COIL14 → at_right_entry
        COIL15 → at_right_exit
    """

    CONVEYOR_SPEED = 0.5
    SPAWN_INTERVAL = (2.0, 5.0)
    TALL_PROBABILITY = 0.4

    def __init__(self, modbus_client, tick_interval_s: float = 0.1) -> None:
        super().__init__(modbus_client, tick_interval_s)
        self.state = HeightSorterState()
        self._spawn_timer = 0.0
        self._next_spawn = random.uniform(*self.SPAWN_INTERVAL)

    def reset(self) -> None:
        self.state = HeightSorterState()
        self._spawn_timer = 0.0
        self._next_spawn = random.uniform(*self.SPAWN_INTERVAL)

    def tick(self) -> None:
        dt = self._tick_interval

        # Read actuator commands from PLC (holding registers, 0/1 as INT)
        entry_regs = self._read_register(0, 1)       # HR0
        entry_on = entry_regs and entry_regs[0] != 0
        tl_regs = self._read_register(3, 1)           # HR3
        transfer_left = tl_regs and tl_regs[0] != 0
        tr_regs = self._read_register(4, 1)           # HR4
        transfer_right = tr_regs and tr_regs[0] != 0

        # Spawn items
        self._spawn_timer += dt
        if self._spawn_timer >= self._next_spawn and self.state.item_position < 0:
            self.state.item_is_tall = random.random() < self.TALL_PROBABILITY
            self.state.item_position = 0.0
            self._spawn_timer = 0.0
            self._next_spawn = random.uniform(*self.SPAWN_INTERVAL)

        # Move item
        if self.state.item_position >= 0 and entry_on:
            self.state.item_position += self.CONVEYOR_SPEED * dt

        # Sensor positions along conveyor
        at_sensor = 0.2 < self.state.item_position < 0.4
        at_pallet = 0.5 < self.state.item_position < 0.7
        past_pallet = self.state.item_position >= 0.8

        # Write height sensor feedback (coils 8-15)
        if at_sensor:
            self._write_discrete(8, self.state.item_is_tall)   # COIL8 = high_sensor
            self._write_discrete(9, True)                       # COIL9 = low_sensor
        else:
            self._write_discrete(8, False)
            self._write_discrete(9, False)

        # Pallet sensor
        self._write_discrete(10, at_pallet)  # COIL10 = pallet_sensor
        self._write_discrete(11, at_pallet)  # COIL11 = loaded

        # Sorting
        if past_pallet:
            if transfer_left:
                self.state.sorted_left += 1
                self.state.item_count += 1
            elif transfer_right:
                self.state.sorted_right += 1
                self.state.item_count += 1
            self.state.item_position = -1.0
