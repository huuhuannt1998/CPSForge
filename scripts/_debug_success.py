"""Debug attack_success column in parquet files."""
import json
import pandas as pd
from pathlib import Path

base = Path("data/raw/v2_online_mitm_level_control")
for d in sorted(base.iterdir()):
    mp = d / "metadata.json"
    pp = d / "unified_steps.parquet"
    if not mp.exists() or not pp.exists():
        continue
    m = json.load(open(mp))
    if (m.get("model_variant") == "base" and 
        m.get("scene_name") == "sorting_weight" and 
        m.get("context_level") == "minimal" and 
        m.get("defense_variant") == "none" and
        m.get("attacker_name", "") == "online_mitm"):
        df = pd.read_parquet(pp)
        attacks = df[df["parsed_decision"] == "attack"]
        writes = df[df["write_executed"] == True]
        print(f"{d.name}: attacks={len(attacks)}, writes={len(writes)}")
        print(f"  attack_success unique: {df['attack_success'].unique()}")
        print(f"  attack_success dtype: {df['attack_success'].dtype}")
        succ_count = df["attack_success"].fillna(False).astype(bool).sum()
        print(f"  attack_success bool sum: {succ_count}")
        succ = df["attack_success"].dropna()
        print(f"  non-null: {len(succ)}, values: {succ.tolist()[:15]}")
        # Check if it's a string column
        print(f"  raw values sample: {df['attack_success'].head(20).tolist()}")
        break
