"""Deeper analysis of FRONTIER parquet data."""
import pandas as pd, json, pathlib

# Minimal context cell
print("=== MINIMAL CONTEXT (no defense) ===")
df1 = pd.read_parquet('data/raw/v2_online_mitm_level_control/20260407T223231Z_556bfe57/unified_steps.parquet')
attack_steps = df1[df1['parsed_decision'].notna()]
print(f"Steps with parsed_decision: {len(attack_steps)}")
# Check for 'attack' decisions
for _, row in df1.iterrows():
    pd_val = row.get('parsed_decision')
    if pd_val and isinstance(pd_val, str) and 'attack' in pd_val.lower():
        print(f"  step={row['step_id']}: decision=attack target={row.get('action_target_tag','?')} "
              f"value={row.get('action_value','?')} write_exec={row.get('write_executed','?')} "
              f"shield={row.get('shield_decision','?')} success={row.get('attack_success','?')}")

# Summarize attack-related columns
print(f"\nwrite_executed values: {df1['write_executed'].value_counts().to_dict()}")
print(f"attack_active values: {df1['attack_active'].value_counts().to_dict()}")
print(f"attack_success values: {df1['attack_success'].value_counts().to_dict()}")
print(f"shield_decision values: {df1['shield_decision'].value_counts().to_dict()}")

# Check what parsed_decision looks like
decisions = df1['parsed_decision'].dropna().unique()
print(f"\nUnique parsed decisions (first 5): {list(decisions[:5])}")

# Full context cell
print("\n\n=== FULL CONTEXT (no defense) ===")
df2 = pd.read_parquet('data/raw/v2_online_mitm_level_control/20260407T223832Z_2d0f295e/unified_steps.parquet')
print(f"write_executed: {df2['write_executed'].value_counts().to_dict()}")
print(f"attack_success: {df2['attack_success'].value_counts().to_dict()}")
print(f"shield_decision: {df2['shield_decision'].value_counts().to_dict()}")
attack_steps = df2[df2['action_target_tag'].notna()]
print(f"Steps with action_target_tag: {len(attack_steps)}")
if len(attack_steps) > 0:
    targets = attack_steps['action_target_tag'].value_counts()
    print(f"Target tags: {targets.to_dict()}")

# LLM Defender cell
print("\n\n=== LLM DEFENDER ===")
df3 = pd.read_parquet('data/raw/v2_online_mitm_level_control/20260407T224215Z_cbc4fe1a/unified_steps.parquet')
print(f"write_executed: {df3['write_executed'].value_counts().to_dict()}")
print(f"llm_defender_blocked: {df3['llm_defender_blocked'].value_counts().to_dict()}")
print(f"shield_decision: {df3['shield_decision'].value_counts().to_dict()}")
print(f"attack_active: {df3['attack_active'].value_counts().to_dict()}")

# Show steps where LLM defender blocked
blocked = df3[df3['llm_defender_blocked'] == True]
print(f"\nLLM defender blocked {len(blocked)} steps")
if len(blocked) > 0:
    print(blocked[['step_id', 'action_target_tag', 'action_value', 'llm_defender_blocked', 'write_executed']].head(10).to_string())

# LLM Combined cell
print("\n\n=== LLM COMBINED ===")
df4 = pd.read_parquet('data/raw/v2_online_mitm_level_control/20260407T224708Z_01403074/unified_steps.parquet')
print(f"write_executed: {df4['write_executed'].value_counts().to_dict()}")
print(f"llm_defender_blocked: {df4['llm_defender_blocked'].value_counts().to_dict()}")
print(f"phase_shield_blocked: {df4['phase_shield_blocked'].value_counts().to_dict()}")
print(f"intent_check_blocked: {df4['intent_check_blocked'].value_counts().to_dict()}")
