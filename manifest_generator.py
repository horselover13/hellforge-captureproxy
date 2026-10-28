import json
import os
import sys

snap = sys.argv[1]
with open(os.path.join(snap, "real-inventory.json"), encoding="utf-8") as handle:
    inventory = json.load(handle)
items = inventory.get("items")
if not isinstance(items, list):
    raise SystemExit("the captured inventory has no items list")

progression_path = os.path.join(snap, "progression.json")
progression = os.path.isfile(progression_path)
experience = None
if progression:
    with open(progression_path, encoding="utf-8") as handle:
        captured = json.load(handle)
    value = captured.get("experience") if isinstance(captured, dict) else None
    if isinstance(value, int) and not isinstance(value, bool):
        experience = value

with open(os.path.join(snap, "seal.json"), encoding="utf-8") as handle:
    seal = json.load(handle)
captured_utc = seal.get("capturedUtc")
if not isinstance(captured_utc, str):
    raise SystemExit("the seal has no capturedUtc")

metadata = {
    "capturedUtc": captured_utc,
    "items": len(items),
    "experience": experience,
    "progression": progression,
}
path = os.path.join(snap, "snapshot.json")
temporary = path + ".tmp"
with open(temporary, "w", encoding="utf-8") as handle:
    json.dump(metadata, handle, indent=2)
    handle.write("\n")
os.replace(temporary, path)
