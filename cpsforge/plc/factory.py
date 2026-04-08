"""
cpsforge.plc.factory
======================
Factory function for creating PLC backend instances.

Selects the appropriate backend (Snap7 or Modbus) based on scene config
or explicit backend specification.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from cpsforge.plc.backend import PlcBackend

logger = logging.getLogger(__name__)


def create_plc_backend(
    backend_type: str = "snap7",
    plc_config=None,
    modbus_config_dict: Optional[Dict[str, Any]] = None,
    event_logger=None,
) -> PlcBackend:
    """
    Create a PLC backend instance.

    Parameters
    ----------
    backend_type:
        "snap7" for Siemens S7 (default) or "modbus" for OpenPLC/Modbus TCP.
    plc_config:
        PLCConfig instance (required for snap7 backend).
    modbus_config_dict:
        Raw dict from modbus.yaml (required for modbus backend).
    event_logger:
        Optional PlcEventLogger for structured event capture.

    Returns
    -------
    PlcBackend
        Connected backend ready for use.
    """
    if backend_type == "snap7":
        from cpsforge.plc.client import PlcClient
        if plc_config is None:
            raise ValueError("plc_config is required for snap7 backend")
        return PlcClient(plc_config, event_logger=event_logger)

    elif backend_type == "modbus":
        from cpsforge.plc.modbus_client import ModbusClient, ModbusConfig
        if modbus_config_dict is None:
            raise ValueError("modbus_config_dict is required for modbus backend")
        config = ModbusConfig.from_dict(modbus_config_dict)
        return ModbusClient(config, event_logger=event_logger)

    else:
        raise ValueError(f"Unknown PLC backend type: {backend_type!r}. "
                         f"Supported: 'snap7', 'modbus'")
