import pandas as pd

df = pd.read_csv("data/processed/detector_comparison/summary.csv")
df = df[df["scene_name"].isin(["level_control", "sorting_weight"])]
df = df[df["detector_type"] != "sequence_model"]

for _, row in df.iterrows():
    print(f'{row["detector_type"]:18s}  {row["scene_name"]:16s}  '
          f'P={row["precision_mean"]:.3f}  R={row["recall_mean"]:.3f}  '
          f'F1={row["f1_mean"]:.3f}  Lat={row["latency_ms_mean"]:.0f}ms  '
          f'FP={row["FP_mean"]:.1f}  FN={row["FN_mean"]:.1f}')
