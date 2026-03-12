"""
CPSForge PLC Polling Loop
==========================
Cyclic tag reader that drives the observation loop.

The PollingLoop connects to the real PLC, reads all scene tags at a
configurable interval, builds PlantSnapshot objects, and pushes them
to a callback or queue for downstream consumption (defenders, loggers, etc.).

Design:
  - Runs in a dedicated thread; shutdown is triggered by a threading.Event.
  - Per-cycle jitter is logged but not fatal.
  - Connection errors trigger reconnect up to the configured retry limit.
  - Every snapshot gets a monotonically increasing step_id.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Callable, List, Optional

from cpsforge.core.config import PLCConfig
from cpsforge.core.models import (
    AttackContext,
    DefenseContext,
    PlantSnapshot,
    SafetyContext,
    SceneProfile,
    TagCategory,
)
from cpsforge.plc.client import PlcClient

logger = logging.getLogger(__name__)

# Type alias for snapshot callbacks
SnapshotCallback = Callable[[PlantSnapshot], None]


class PollingLoop:
    """
    Runs a cyclic read of all scene tags against the real PLC.

    Parameters
    ----------
    plc_client:
        A connected (or connectable) :class:`PlcClient`.
    scene:
        The :class:`SceneProfile` defining which tags to poll.
    run_id:
        Unique identifier for the current experiment run.
    interval_ms:
        Polling interval in milliseconds. Defaults to scene.sampling_interval_ms.
    on_snapshot:
        Optional callback invoked with each fresh :class:`PlantSnapshot`.
    """

    def __init__(
        self,
        plc_client: PlcClient,
        scene: SceneProfile,
        run_id: str,
        interval_ms: Optional[int] = None,
        on_snapshot: Optional[SnapshotCallback] = None,
    ) -> None:
        self._client = plc_client
        self._scene = scene
        self._run_id = run_id
        self._interval_s = (interval_ms or scene.sampling_interval_ms) / 1000.0
        self._on_snapshot = on_snapshot

        self._step_id: int = 0
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Latest snapshot (thread-safe read via property)
        self._latest_snapshot: Optional[PlantSnapshot] = None
        self._snapshot_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Control
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the polling loop in a background thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("PollingLoop already running.")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name=f"plc-poll-{self._scene.scene_name}",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "PollingLoop started for scene '%s' (interval=%.3fs, run_id=%s)",
            self._scene.scene_name,
            self._interval_s,
            self._run_id,
        )

    def stop(self, timeout_s: float = 5.0) -> None:
        """Signal the polling loop to stop and wait for thread exit."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout_s)
            if self._thread.is_alive():
                logger.warning("PollingLoop thread did not stop within %.1fs", timeout_s)
            else:
                logger.info("PollingLoop stopped.")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    # ------------------------------------------------------------------
    # Latest snapshot (safe read from any thread)
    # ------------------------------------------------------------------

    @property
    def latest_snapshot(self) -> Optional[PlantSnapshot]:
        with self._snapshot_lock:
            return self._latest_snapshot

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            cycle_start = time.monotonic()
            snapshot = self._poll_once()
            if snapshot is not None:
                with self._snapshot_lock:
                    self._latest_snapshot = snapshot
                if self._on_snapshot:
                    try:
                        self._on_snapshot(snapshot)
                    except Exception as exc:
                        logger.error("Snapshot callback raised: %s", exc)
                self._step_id += 1

            elapsed = time.monotonic() - cycle_start
            sleep_s = max(0.0, self._interval_s - elapsed)
            if elapsed > self._interval_s * 1.5:
                logger.debug(
                    "Polling cycle took %.3fs (target=%.3fs) -- jitter detected",
                    elapsed,
                    self._interval_s,
                )
            self._stop_event.wait(sleep_s)

    def _poll_once(self) -> Optional[PlantSnapshot]:
        """Read all scene tags and build a PlantSnapshot."""
        try:
            raw = self._client.read_many(self._scene.tags)
        except Exception as exc:
            logger.error("PLC read_many failed: %s", exc)
            return None

        sensors: dict = {}
        actuators: dict = {}
        controller_state: dict = {}
        alarms: dict = {}
        setpoints: dict = {}

        for tag in self._scene.tags:
            val = raw.get(tag.name)
            bucket = {
                TagCategory.SENSOR: sensors,
                TagCategory.ACTUATOR: actuators,
                TagCategory.MODE_BIT: controller_state,
                TagCategory.INTERNAL: controller_state,
                TagCategory.ALARM: alarms,
                TagCategory.SETPOINT: setpoints,
            }.get(tag.category, controller_state)
            bucket[tag.name] = val

        return PlantSnapshot(
            timestamp=datetime.now(timezone.utc),
            scene_name=self._scene.scene_name,
            run_id=self._run_id,
            step_id=self._step_id,
            sensors=sensors,
            actuators=actuators,
            controller_state=controller_state,
            alarms=alarms,
            setpoints=setpoints,
            attack_context=AttackContext(),
            defense_context=DefenseContext(),
            safety_context=SafetyContext(
                live_writes_enabled=self._client._config.live_writes_enabled
            ),
        )
