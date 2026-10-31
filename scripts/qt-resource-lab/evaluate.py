"""Compare predictions with final-image truth, without passing truth to scanners."""
from collections import Counter
from model import read_jsonl


def file_key(record):
    return (record["path"], record["offset"])


def compare_sample(label, prediction):
    result = {"id": label["id"], "status": "unknown", "tp": 0, "fp": 0, "fn": 0,
              "duplicates": 0, "content_mismatches": 0, "bundle_tp": 0, "bundle_fp": 0,
              "bundle_fn": 0, "file_tp": 0, "file_fp": 0, "file_fn": 0}
    result["scannerStatus"] = failure_status(prediction)
    if label["status"] not in ("verified", "partial"):
        return result
    if prediction is None or prediction.get("status") != "ok":
        result["status"] = failure_status(prediction)
        return result
    result["status"] = "partial-evaluated" if label["status"] == "partial" else "evaluated"
    result.update(compare_files(label, prediction))
    positive = bool(label["files"] or label["bundles"])
    result["file_tp"] = int(positive and bool(prediction["bundles"]))
    result["file_fp"] = int(not positive and bool(prediction["bundles"]))
    result["file_fn"] = int(positive and not prediction["bundles"])
    result.update(bundle_metrics(label, prediction))
    return result


def failure_status(prediction):
    return "missing" if prediction is None else prediction.get("status", "error")


def compare_files(label, prediction):
    result = {}
    expected = Counter(file_key(item) for item in label["files"])
    predicted_files = [item for bundle in prediction["bundles"] for item in bundle["files"]]
    predicted_files, result["unscored_files"] = scoped_files(label, predicted_files, expected)
    found = Counter(file_key(item) for item in predicted_files)
    result["tp"] = sum((expected & found).values())
    result["fn"] = sum((expected - found).values())
    result["fp"] = sum((found - expected).values())
    result["duplicates"] = sum(max(0, count - max(1, expected[key])) for key, count in found.items())
    result["content_mismatches"] = result["tp"] - content_matches(label["files"], predicted_files)
    result["metadata_mismatches"] = metadata_mismatches(label, prediction)
    return result


def bundle_metrics(label, prediction):
    result = {}
    if label.get("bundleStatus", "verified") == "verified":
        result.update(compare_bundles(label, prediction))
        if label["status"] == "partial":
            result["bundle_unscored"] = result["bundle_fp"]
            result["bundle_fp"] = 0
    else:
        result["bundle_unscored"] = 1
    return result


def scoped_files(label, predicted_files, expected):
    if label["status"] != "partial":
        return predicted_files, 0
    unknown = sum(file_key(item) not in expected for item in predicted_files)
    return [item for item in predicted_files if file_key(item) in expected], unknown


def content_matches(expected, found):
    correct = Counter((*file_key(item), item["sha256"]) for item in expected)
    reported = Counter((*file_key(item), item["sha256"]) for item in found)
    return sum((correct & reported).values())


def metadata_mismatches(label, prediction):
    expected = Counter((*file_key(item), item["language"], item["territory"])
                       for item in label["files"] if "language" in item and "territory" in item)
    found = Counter((*file_key(item), item.get("language"), item.get("territory"))
                    for bundle in prediction["bundles"] for item in bundle["files"])
    identities = {(key[0], key[1]) for key in found}
    return sum(count for key, count in (expected - found).items() if (key[0], key[1]) in identities)


def compare_bundles(label, prediction):
    unmatched = list(label["bundles"])
    matched = 0
    for bundle in prediction["bundles"]:
        offsets = {item.get("offset") for item in bundle["files"]}
        match = next((item for item in unmatched if offsets & set(item["payloadOffsets"])), None)
        if match is not None:
            unmatched.remove(match)
            matched += 1
    return {"bundle_tp": matched, "bundle_fp": len(prediction["bundles"]) - matched,
            "bundle_fn": len(unmatched)}


def evaluate(labels, predictions):
    by_id = {}
    duplicate_ids = []
    for prediction in predictions:
        if prediction["id"] in by_id:
            duplicate_ids.append(prediction["id"])
        by_id[prediction["id"]] = prediction
    if duplicate_ids:
        raise ValueError(f"Repeated prediction ids: {duplicate_ids[:3]}")
    known = {label["id"] for label in labels}
    if set(by_id) - known:
        raise ValueError("Predictions contain unknown sample ids")
    return [compare_sample(label, by_id.get(label["id"])) for label in labels]


def evaluate_files(labels_path, predictions_path):
    return evaluate(read_jsonl(labels_path), read_jsonl(predictions_path))
