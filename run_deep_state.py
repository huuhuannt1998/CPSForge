"""Quick launcher: Deep State MITM attacker vs Factory I/O Level Control on OpenPLC."""

import sys
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("deep_state_launcher")

sys.path.insert(0, str(Path(__file__).parent))

from cpsforge.core.config import ConfigLoader
from cpsforge.runner.online_runner import OnlineExperimentRunner

loader = ConfigLoader(configs_dir=Path("configs"))
exp_cfg = loader.load_experiment("v2_online")

# Scene: level_control on OpenPLC (Modbus TCP → Factory I/O)
exp_cfg.scene_config = "scenes/level_control_openplc.yaml"
exp_cfg.live_writes_enabled = True   # Real writes to PLC
exp_cfg.dry_run = False

extra = {
    "context_level": "full",
    "model_variant": "base",
    "finetune_status": "base",
    "defense_variant": "none",        # No defense — raw attacker capability
    "attack_budget": 10,
    "decision_interval_steps": 3,
    "attacker_type": "deep_state_mitm",
    "use_simulator": False,             # Factory I/O provides physics
}

logger.info("Launching Deep State MITM vs level_control_openplc (LIVE writes)")
logger.info("Factory I/O should be running with Level Control scene connected")

runner = OnlineExperimentRunner(
    config=exp_cfg,
    loader=loader,
    output_base=Path("data/raw"),
    extra=extra,
)

run_id = runner.run()
logger.info("Run complete: %s", run_id)
