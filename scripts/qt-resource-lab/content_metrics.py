"""Content discovery metrics independent of inferred resource names and hierarchy."""


def compare_contents(label, prediction):
    expected = {(entry["offset"], entry["sha256"]) for entry in label["files"]}
    found = [(entry["offset"], entry["sha256"]) for bundle in prediction["bundles"] for entry in bundle["files"]]
    offsets = {offset for offset, _ in expected}
    scored = [entry for entry in found if label["status"] != "partial" or entry[0] in offsets]
    actual = set(scored)
    expected_hashes = {sha for _, sha in expected}
    actual_hashes = {sha for _, sha in actual}
    return {"content_unique_tp": len(expected_hashes & actual_hashes),
            "content_unique_fp": len(actual_hashes - expected_hashes),
            "content_unique_fn": len(expected_hashes - actual_hashes),
            "payload_tp": len(expected & actual), "payload_fp": len(actual - expected),
            "payload_fn": len(expected - actual), "content_duplicates": len(scored) - len(actual),
            "content_unscored": len(found) - len(scored)}
