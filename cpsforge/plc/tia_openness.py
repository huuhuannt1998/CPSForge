"""
tia_openness.py — TIA Portal Openness API interface for programmatic PLC code deployment.

Provides a Python wrapper around Siemens TIA Portal Openness V17 to:
  - Attach to a running TIA Portal instance
  - Back up existing function blocks (XML export)
  - Import modified SCL source into the project
  - Generate (compile SCL→blocks) and compile the full project
  - Restore original code from backup

This module is the execution backend for logic-level attacks:
the LLM generates adversarial SCL, and this module deploys it to the PLC.

Requirements:
  - TIA Portal V17 running with project open
  - TIA Openness V17 DLLs installed
  - pythonnet (clr) available
  - Project must have non-optimized DBs for external source import

Note: Download-to-PLC is performed manually from the TIA Portal UI after
compilation, because the Openness Download API requires .NET delegates
that pythonnet cannot satisfy reliably.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# DLL paths for TIA Openness V17
CONTRACT_DLL = r"C:\Program Files\Siemens\Automation\Portal V17\Bin\PublicAPI\Siemens.Engineering.Contract.dll"
ENGINEERING_DLL = r"C:\Program Files\Siemens\Automation\Portal V17\PublicAPI\V17\Siemens.Engineering.dll"


def _load_assemblies():
    """Load TIA Openness .NET assemblies (Contract first, then Engineering)."""
    import clr
    clr.AddReference(CONTRACT_DLL)
    clr.AddReference(ENGINEERING_DLL)


class TiaOpennessClient:
    """Interface to TIA Portal Openness V17 for SCL deployment.

    Parameters
    ----------
    backup_dir : Path
        Directory for XML backups of original blocks.
    scl_staging_dir : Path
        Directory for staging modified SCL files before import.
    """

    def __init__(
        self,
        backup_dir: Optional[Path] = None,
        scl_staging_dir: Optional[Path] = None,
    ) -> None:
        self._backup_dir = backup_dir or Path("data/processed/tia_openness/backups")
        self._scl_staging_dir = scl_staging_dir or Path("data/processed/tia_openness/staging")
        self._backup_dir.mkdir(parents=True, exist_ok=True)
        self._scl_staging_dir.mkdir(parents=True, exist_ok=True)

        self._tia = None
        self._project = None
        self._plc_sw = None
        self._plc_item = None
        self._attached = False

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def attach(self) -> bool:
        """Attach to the first running TIA Portal instance and its project.

        Returns True on success, False if no TIA Portal process found.
        """
        _load_assemblies()

        from Siemens.Engineering import TiaPortal
        from Siemens.Engineering.HW.Features import SoftwareContainer

        processes = TiaPortal.GetProcesses()
        if processes.Count == 0:
            logger.error("No TIA Portal process found.")
            return False

        self._tia = processes[0].Attach()
        if self._tia.Projects.Count == 0:
            logger.error("TIA Portal has no open project.")
            return False

        self._project = self._tia.Projects[0]
        logger.info("Attached to project: %s", self._project.Name)

        # Find the PLC software container
        for dev in self._project.Devices:
            for item in dev.DeviceItems:
                sc = item.GetService[SoftwareContainer]()
                if sc and sc.Software:
                    self._plc_sw = sc.Software
                    self._plc_item = item
                    break
            if self._plc_sw:
                break

        if not self._plc_sw:
            logger.error("No PLC software found in project.")
            return False

        self._attached = True
        logger.info("PLC software located. Ready for operations.")
        return True

    @property
    def attached(self) -> bool:
        return self._attached

    # ------------------------------------------------------------------
    # Backup
    # ------------------------------------------------------------------

    def backup_block(self, block_name: str) -> Optional[Path]:
        """Export a function block as XML for backup.

        Returns the backup file path, or None on failure.
        """
        if not self._attached:
            logger.error("Not attached to TIA Portal.")
            return None

        from Siemens.Engineering import ExportOptions
        from System.IO import FileInfo

        block = self._find_block(block_name)
        if block is None:
            logger.error("Block '%s' not found.", block_name)
            return None

        backup_path = (self._backup_dir / f"{block_name}_original.xml").resolve()
        if backup_path.exists():
            os.remove(str(backup_path))

        fi = FileInfo(str(backup_path))
        block.Export(fi, ExportOptions.WithDefaults)

        size = backup_path.stat().st_size
        logger.info("Backed up %s → %s (%d bytes)", block_name, backup_path, size)
        return backup_path

    # ------------------------------------------------------------------
    # Import + Compile
    # ------------------------------------------------------------------

    def deploy_scl(self, scl_content: str, source_name: str) -> Tuple[bool, str]:
        """Deploy modified SCL to the TIA project.

        Steps:
          1. Write SCL to staging file
          2. Delete existing external source with same name (if any)
          3. Import via CreateFromFile
          4. GenerateBlocksFromSource (SCL → PLC blocks)
          5. Compile full project

        Parameters
        ----------
        scl_content : str
            Complete SCL source code (must be valid for TIA Portal V17).
        source_name : str
            Name for the external source (e.g., "FB_LevelControl.scl").

        Returns
        -------
        (success, message) : Tuple[bool, str]
            success is True if compilation has 0 errors.
        """
        if not self._attached:
            return False, "Not attached to TIA Portal."

        from Siemens.Engineering.Compiler import ICompilable

        # Step 1: Write SCL to staging file
        scl_path = (self._scl_staging_dir / source_name).resolve()
        scl_path.write_text(scl_content, encoding="utf-8")
        logger.info("Wrote SCL to staging: %s (%d chars)", scl_path, len(scl_content))

        # Step 2: Delete existing external source with same name
        try:
            sources = self._plc_sw.ExternalSourceGroup.ExternalSources
            for s in sources:
                if s.Name == source_name:
                    s.Delete()
                    logger.info("Deleted existing source: %s", source_name)
                    break
        except Exception as exc:
            logger.warning("Failed to clean up existing source: %s", exc)

        # Step 3: Import SCL
        try:
            new_source = self._plc_sw.ExternalSourceGroup.ExternalSources.CreateFromFile(
                source_name, str(scl_path)
            )
            logger.info("Imported source: %s", new_source.Name)
        except Exception as exc:
            return False, f"Import failed: {exc}"

        # Step 4: Generate blocks from source
        try:
            new_source.GenerateBlocksFromSource()
            logger.info("Generated blocks from source.")
        except Exception as exc:
            return False, f"Block generation failed: {exc}"

        # Step 5: Compile
        try:
            compilable = self._plc_sw.GetService[ICompilable]()
            result = compilable.Compile()
            state = str(result.State)
            msg_count = result.Messages.Count

            # Count errors
            errors = 0
            error_msgs = []
            for msg in result.Messages:
                msg_str = str(msg)
                if "error" in msg_str.lower():
                    errors += 1
                    error_msgs.append(msg_str)

            if errors > 0:
                detail = "; ".join(error_msgs[:3])
                return False, f"Compilation failed: {errors} error(s). {detail}"

            logger.info("Compiled: state=%s, messages=%d, errors=%d", state, msg_count, errors)
            return True, f"Compiled successfully (state={state}, {msg_count} messages, 0 errors)"

        except Exception as exc:
            return False, f"Compilation exception: {exc}"

    # ------------------------------------------------------------------
    # Restore
    # ------------------------------------------------------------------

    def restore_block(self, block_name: str, original_scl_path: Path) -> Tuple[bool, str]:
        """Restore a block from the original SCL source file.

        Parameters
        ----------
        block_name : str
            Block name (e.g., "FB_LevelControl").
        original_scl_path : Path
            Path to the original SCL file.

        Returns
        -------
        (success, message) : Tuple[bool, str]
        """
        source_name = f"{block_name}.scl"
        scl_content = original_scl_path.read_text(encoding="utf-8")
        return self.deploy_scl(scl_content, source_name)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _find_block(self, block_name: str):
        """Find a block by name in the PLC program."""
        for block in self._plc_sw.BlockGroup.Blocks:
            if block.Name == block_name:
                return block
        return None

    def list_blocks(self):
        """List all block names and types."""
        if not self._attached:
            return []
        result = []
        for block in self._plc_sw.BlockGroup.Blocks:
            result.append((block.Name, type(block).__name__))
        return result

    def list_external_sources(self):
        """List all external source names."""
        if not self._attached:
            return []
        return [s.Name for s in self._plc_sw.ExternalSourceGroup.ExternalSources]
