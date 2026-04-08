import json
ckpt = json.load(open("data/checkpoint.json"))
frontier = [c for c in ckpt["completed"] if "FRONTIER" in c]
print(f"Total FRONTIER: {len(frontier)}/45")
print(f"Total checkpoint: {len(ckpt['completed'])}")
# Break down by scene
lc = [c for c in frontier if "level_control" in c]
sw = [c for c in frontier if "sorting_weight" in c]
sh = [c for c in frontier if "sorting_height" in c]
print(f"  Level Control:       {len(lc)}/15")
print(f"  Sorting Weight:      {len(sw)}/15")
print(f"  Sorting Height:      {len(sh)}/15")
