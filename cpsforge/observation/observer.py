"""
observer.py — Unified PLC state observer.

PlcObserver wraps the existing PollingLoop and exposes the latest snapshot
plus a HistoryBuffer to the online MITM attacker.  It is intentionally
thin — all validation, phase inference, and context building happen in
separate modules.
"""

from __future__ import annotations

import logging
from typing import Callable, List, Optional

from cpsforge.core.config import PLCConfig
from cpsforge.core.models import PlantSnapshot
from cpsforge.observation.history_buffer import HistoryBuffer
from cpsforge.plc.client import PlcClient
from cpsforge.plc.poller import PollingLoop
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)


class PlcObserver:
    """Observe a live PLC process and maintain a rolling history.

    Usage
    -----
    ```python
    observer = PlcObserver(plc_client, scene, run_id, history_size=50)
    observer.start()

    latest = observer.latest()           # most recent snapshot
    window = observer.history.window(20) # last 20 snapshots
    observer.stop()
    ```
    """

    def __init__(
        self,
        plc_client: PlcClient,
        scene: BaseScene,
        run_id: str,
        history_size: int = 50,
        on_snapshot: Optional[Callable[[PlantSnapshot], None]] = None,
    ) -> None:
        self._plc = plc_client
        self._scene = scene
        self._run_id = run_id
        self._history = HistoryBuffer(max_size=history_size)
        self._extra_callback = on_snapshot

        # PollingLoop drives the underlying PLC read cycle
        self._poller = PollingLoop(
            plc_client=plc_client,
            scene=scene.profile,
            run_id=run_id,
            on_snapshot=self._on_snapshot,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background polling thread."""
        self._poller.start()
        logger.debug("PlcObserver started for run %s", self._run_id)

    def stop(self, timeout_s: float = 5.0) -> None:
        """Stop the background polling thread."""
        self._poller.stop(timeout_s=timeout_s)
        logger.debug("PlcObserver stopped for run %s", self._run_id)

    def is_running(self) -> bool:
        return self._poller.is_running()

    # ------------------------------------------------------------------
    # Data access
    # ------------------------------------------------------------------

    @property
    def history(self) -> HistoryBuffer:
        """Access the rolling history buffer."""
        return self._history

    def latest(self) -> Optional[PlantSnapshot]:
        """Return the most recently polled snapshot."""
        return self._poller.latest_snapshot

    def window(self, n: Optional[int] = None) -> List[PlantSnapshot]:
        """Return the last *n* snapshots from the history buffer."""
        return self._history.window(n)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _on_snapshot(self, snapshot: PlantSnapshot) -> None:
        """Called by PollingLoop on each new reading."""
        # Enrich with derived features from the scene
        snapshot.derived_features = self._scene.extract_derived_features(snapshot)
        self._history.append(snapshot)
        if self._extra_callback is not None:
            try:
                self._extra_callback(snapshot)
            except Exception:
                logger.exception("on_snapshot callback raised an exception")
