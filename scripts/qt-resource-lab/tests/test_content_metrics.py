from copy import deepcopy
import unittest
from content_metrics import compare_contents


def truth():
    return {"status": "verified", "files": [{"offset": 100, "sha256": "first"},
                                              {"offset": 200, "sha256": "second"}]}


def reply():
    return {"bundles": [{"files": [{"offset": 100, "sha256": "first", "path": "/wrong-name"},
                                    {"offset": 200, "sha256": "second", "path": "/other"}]}]}


class ContentMetricsTests(unittest.TestCase):
    def test_paths_and_locales_do_not_change_content_metrics(self):
        result = compare_contents(truth(), reply())
        self.assertEqual(result, {"content_unique_tp": 2, "content_unique_fp": 0, "content_unique_fn": 0,
                                  "payload_tp": 2, "payload_fp": 0, "payload_fn": 0,
                                  "content_duplicates": 0, "content_unscored": 0})

    def test_duplicates_do_not_inflate_recall(self):
        found = reply()
        found["bundles"].append(deepcopy(found["bundles"][0]))
        result = compare_contents(truth(), found)
        self.assertEqual((result["content_unique_tp"], result["payload_tp"], result["content_duplicates"]), (2, 2, 2))

    def test_missing_extra_and_wrong_hash_are_distinct(self):
        found = reply()
        found["bundles"][0]["files"] = [{"offset": 100, "sha256": "wrong"}, {"offset": 999, "sha256": "extra"}]
        result = compare_contents(truth(), found)
        self.assertEqual((result["content_unique_tp"], result["content_unique_fp"], result["content_unique_fn"]), (0, 2, 2))
        self.assertEqual((result["payload_tp"], result["payload_fp"], result["payload_fn"]), (0, 2, 2))

    def test_same_content_at_another_location_is_separate_from_payload(self):
        found = reply()
        found["bundles"][0]["files"][0]["offset"] = 300
        result = compare_contents(truth(), found)
        self.assertEqual((result["content_unique_tp"], result["content_unique_fp"]), (2, 0))
        self.assertEqual((result["payload_tp"], result["payload_fp"], result["payload_fn"]), (1, 1, 1))

    def test_expected_duplicate_content_is_counted_once(self):
        label = truth()
        label["files"].append({"offset": 300, "sha256": "first"})
        found = reply()
        found["bundles"][0]["files"].append({"offset": 300, "sha256": "first"})
        result = compare_contents(label, found)
        self.assertEqual((result["content_unique_tp"], result["payload_tp"], result["content_duplicates"]), (2, 3, 0))

    def test_partial_truth_does_not_turn_unknown_payload_into_fp(self):
        label = truth()
        label["status"] = "partial"
        found = reply()
        found["bundles"][0]["files"].append({"offset": 300, "sha256": "unknown"})
        result = compare_contents(label, found)
        self.assertEqual((result["content_unique_tp"], result["content_unique_fp"], result["payload_fp"], result["content_unscored"]), (2, 0, 0, 1))

    def test_partial_truth_still_detects_wrong_hash_at_known_offset(self):
        label = truth()
        label["status"] = "partial"
        found = reply()
        found["bundles"][0]["files"][0]["sha256"] = "wrong"
        result = compare_contents(label, found)
        self.assertEqual((result["content_unique_fp"], result["payload_fp"], result["content_unscored"]), (1, 1, 0))

    def test_no_files_is_a_valid_empty_comparison(self):
        result = compare_contents({"status": "verified", "files": []}, {"bundles": []})
        self.assertTrue(all(value == 0 for value in result.values()))
