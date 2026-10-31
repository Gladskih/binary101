"""Deduplicated totals, nonadditive configuration strata and small observed reproductions."""
from collections import Counter
import json
from pathlib import Path
from model import read_jsonl, write_json


def numbers(rows):
    totals = Counter()
    for row in rows:
        totals.update({key: value for key, value in row.items() if isinstance(value, int)})
        totals[row["status"]] += 1
    return dict(totals)


def unique_observations(labels, evaluations):
    by_id = {row["id"]: row for row in evaluations}
    seen, selected = set(), []
    for label in labels:
        if label["sha256"] not in seen:
            seen.add(label["sha256"])
            if label["id"] in by_id:
                selected.append((label, by_id[label["id"]]))
    return seen, selected


def stratum(label):
    producer = label.get("producer", {})
    return "/".join(str(value) for value in (label["format"], producer.get("sdk", "real"),
                    producer.get("compiler", "unknown"), producer.get("target", "unknown"),
                    producer.get("profile", "unknown"), label["family"], label["variant"]))


def stratified(labels, evaluations):
    by_id = {row["id"]: row for row in evaluations}
    groups, seen = {}, set()
    for label in labels:
        identity = (stratum(label), label["sha256"])
        if identity in seen or label["id"] not in by_id:
            continue
        seen.add(identity)
        groups.setdefault(identity[0], []).append(by_id[label["id"]])
    return {key: numbers(rows) for key, rows in groups.items()}


def has_discrepancy(row):
    return any((row["status"] in ("error", "timeout", "missing", "unsupported"),
                row["fp"], row["fn"], row["content_mismatches"], row.get("metadata_mismatches", 0)))


def reproductions(output, observations):
    rows = sorted((pair for pair in observations if has_discrepancy(pair[1])),
                  key=lambda pair: Path(pair[0]["path"]).stat().st_size)
    selected, seen = [], set()
    for label, result in rows:
        key = (label["format"], label["family"], label["variant"], result["status"])
        if key in seen or not has_discrepancy(result):
            continue
        seen.add(key)
        record = {"input": {key: label[key] for key in ("id", "path", "sha256")},
                  "expected": label, "evaluation": result,
                  "job": str(output / "jobs" / label.get("caseId", "shipping") / "job.json")}
        path = output / "repro" / (label["id"] + ".json")
        write_json(path, record)
        selected.append({"id": label["id"], "caseId": label.get("caseId", label["id"]),
                         "path": str(path), "fp": result["fp"], "fn": result["fn"]})
        if len(selected) == 12:
            break
    return selected


def build_runs(output):
    result = {}
    for name in ("smoke", "pilot", "build"):
        path = output / f"{name}-run.json"
        if path.is_file():
            result[name] = json.loads(path.read_text(encoding="utf-8"))
    return result


def denominators(observations):
    verified = [(label, row) for label, row in observations
                if label["status"] == "verified" and row["status"] == "evaluated"]
    positive = sum(bool(label["files"] or label["bundles"]) for label, _ in verified)
    return {"evaluatedCompleteInputs": len(verified), "positiveInputs": positive,
            "negativeInputs": len(verified) - positive,
            "expectedResourceFiles": sum(len(label["files"]) for label, _ in verified),
            "expectedBundles": sum(len(label["bundles"]) for label, _ in verified)}


def split_totals(observations):
    groups = {}
    for label, row in observations:
        groups.setdefault(label["split"], []).append(row)
    return {name: numbers(rows) for name, rows in groups.items()}


def report(output):
    labels = read_jsonl(output / "labels.jsonl")
    evaluation_path = output / "evaluation.json"
    evaluations = json.loads(evaluation_path.read_text(encoding="utf-8")) if evaluation_path.is_file() else []
    hashes, observations = unique_observations(labels, evaluations)
    totals = numbers([row for _, row in observations])
    truth_counts = Counter(label["status"] for label, _ in observations)
    result = {"samples": len(labels), "uniqueSha256": len(hashes), "truthCounts": dict(truth_counts),
              "families": sorted({row["family"] for row in labels}), "totals": totals,
              "strata": stratified(labels, evaluations), "buildRuns": build_runs(output),
              "denominators": denominators(observations), "splits": split_totals(observations),
              "scannerStatuses": dict(Counter(row.get("scannerStatus", "not-recorded") for _, row in observations)),
              "discrepancies": reproductions(output, observations),
              "limits": "Correlated variants; 0/N does not prove zero FP. Unknown truth is excluded; strata are nonadditive. Repros are smallest observed, not globally minimized."}
    write_json(output / "summary.json", result)
    if (output / "doctor.json").is_file():
        from markdown import write_markdown
        write_markdown(output, result)
    return {key: value for key, value in result.items() if key != "strata"}
