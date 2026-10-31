"""A failed/stale pilot cannot authorize the larger build investment."""
import json
from controller import recipe_hash
from model import read_jsonl, write_json


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def pilot_inputs(output, kits):
    cases = {row["id"] for row in read(output / "pilot-schedule.json")}
    required = {row["id"]: row["sha256"] for row in read_jsonl(output / "labels.jsonl") if row.get("caseId") in cases}
    evaluated = {row["id"] for row in read(output / "evaluation.json") if row["status"] == "evaluated"}
    current = recipe_hash()
    recipes = [read(output / "jobs" / identity / "result.json") for identity in cases]
    compiler_versions = {sdk["id"]: sdk["compilerVersions"] for sdk in kits}
    valid = all(record.get("recipeSha256") == current and
                record["sdk"]["compilerVersions"] == compiler_versions[record["job"]["sdk"]] for record in recipes)
    return required, evaluated, valid


def gate(output):
    run = read(output / "pilot-run.json")
    kits = read(output / "doctor.json")["sdks"]
    complete = len({(sdk["format"], sdk["major"], sdk["linkage"]) for sdk in kits}) == 8
    from selftest import selftest
    tests = selftest(output)
    required, evaluated, current_recipes = pilot_inputs(output, kits)
    passed = all((run["status"] == "completed", run["built"] == run["attempted"],
                  run["cpuCapacityFraction"] >= 0.5, tests["passed"], complete,
                  bool(required), set(required) <= evaluated, current_recipes))
    result = {"passed": passed, "sdkIds": sorted(s["id"] for s in kits),
              "recipeSha256": recipe_hash(), "pilotSamples": required,
              "sdkFingerprints": {sdk["id"]: sdk["fingerprint"] for sdk in kits},
              "sdkCompilerVersions": {sdk["id"]: sdk["compilerVersions"] for sdk in kits},
              "completeSdkMatrix": complete, "cpuCapacityFraction": run["cpuCapacityFraction"],
              "reason": "passed" if passed else "Check pilot-run, selftest, evaluation, and missing SDK cells"}
    write_json(output / "pilot-gate.json", result)
    return result
