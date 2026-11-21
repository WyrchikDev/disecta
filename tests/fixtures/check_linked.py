"""Validate recovery of the named function and import in a compiled linked.c fixture."""
import argparse
import json
from pathlib import Path
import subprocess


def inspect(tool, image, command, *args):
    result = subprocess.run([tool, command, image, *args, "--json"], check=True, capture_output=True)
    return json.loads(result.stdout)


def verify(tool, image):
    metadata = inspect(tool, image, "inspect")
    expected_import = "GetCurrentProcessId" if metadata["format"] == "PE32+" else "fixture_external_value"
    report = inspect(tool, image, "analyze")
    functions = [entry for entry in report["functions"] if "fixture_adjust" in entry["names"]]
    if len(functions) != 1 or report["limited"]:
        raise SystemExit(f"{image}: expected one complete fixture_adjust candidate")
    entry = functions[0]["address"]
    graph = inspect(tool, image, "cfg", "--function", entry)
    slots = [address for address, name in report["import_slots"].items() if name["name"] == expected_import]
    if not graph["blocks"] or graph["entry_status"]:
        raise SystemExit(f"{image}: no CFG recovered at {entry}")
    if not slots or not any(ref["target"] in slots and ref["target_kind"] == "import_slot"
                            for ref in report["references"]):
        raise SystemExit(f"{image}: no reference to {expected_import}")
    print(f"{image.name}: fixture_adjust at {entry}, {len(graph['blocks'])} blocks, {expected_import} referenced")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disecta", type=Path)
    parser.add_argument("images", type=Path, nargs="+")
    args = parser.parse_args()
    binary = args.disecta.resolve(strict=True)
    for image in args.images:
        verify(binary, image)
