import unittest
from evaluate import compare_sample, evaluate


def label():
    return {"id": "sample", "status": "verified", "files": [{"path": "/a", "sha256": "abc", "offset": 100}],
            "bundles": [{"payloadOffsets": [100]}]}


def prediction():
    return {"id": "sample", "status": "ok", "bundles": [{"files": [{"path": "/a", "sha256": "abc", "offset": 100}]}]}


class EvaluateTests(unittest.TestCase):
    def test_exact(self):
        result = compare_sample(label(), prediction())
        self.assertEqual((result["tp"], result["fp"], result["fn"], result["bundle_tp"]), (1, 0, 0, 1))
        self.assertEqual((result["content_mismatches"], result["unscored_files"], result["duplicates"]), (0, 0, 0))
        self.assertEqual((result["file_tp"], result["file_fp"], result["file_fn"]), (1, 0, 0))

    def test_missing(self):
        result = compare_sample(label(), {"id": "sample", "status": "ok", "bundles": []})
        self.assertEqual((result["fn"], result["file_fn"], result["bundle_fn"]), (1, 1, 1))
        self.assertEqual((result["tp"], result["file_tp"], result["file_fp"]), (0, 0, 0))

    def test_extra(self):
        truth = label()
        truth.update(files=[], bundles=[])
        result = compare_sample(truth, prediction())
        self.assertEqual((result["fp"], result["file_fp"], result["bundle_fp"]), (1, 1, 1))
        self.assertEqual((result["file_tp"], result["file_fn"]), (0, 0))

    def test_wrong_content(self):
        found = prediction()
        found["bundles"][0]["files"][0]["sha256"] = "wrong"
        result = compare_sample(label(), found)
        self.assertEqual((result["content_mismatches"], result["tp"], result["fp"], result["fn"]), (1, 1, 0, 0))

    def test_duplicates(self):
        found = prediction()
        found["bundles"].append(found["bundles"][0])
        result = compare_sample(label(), found)
        self.assertEqual((result["duplicates"], result["bundle_fp"]), (1, 1))

    def test_unknown_is_not_negative(self):
        truth = label()
        truth["status"] = "unknown"
        result = compare_sample(truth, prediction())
        self.assertEqual((result["status"], result["fp"]), ("unknown", 0))
        self.assertTrue(all(value == 0 for value in result.values() if isinstance(value, int)))

    def test_unknown_truth_does_not_hide_scanner_errors(self):
        truth = label()
        truth["status"] = "unknown"
        result = compare_sample(truth, {"status": "timeout"})
        self.assertEqual((result["status"], result["scannerStatus"], result["fp"]), ("unknown", "timeout", 0))

    def test_partial_inventory_does_not_invent_false_positives(self):
        truth = label()
        truth["status"] = "partial"
        found = prediction()
        found["bundles"].append({"files": [{"path": "/unknown", "sha256": "def", "offset": 200}]})
        result = compare_sample(truth, found)
        self.assertEqual((result["status"], result["fp"], result["unscored_files"]), ("partial-evaluated", 0, 1))
        self.assertEqual((result["bundle_fp"], result["bundle_unscored"]), (0, 1))
        found["bundles"].append({"files": [{"path": "/other", "sha256": "ghi", "offset": 300}]})
        self.assertEqual(compare_sample(truth, found)["unscored_files"], 2)

    def test_one_extra_file_does_not_count_as_a_correct_match(self):
        found = prediction()
        found["bundles"][0]["files"].append({"path": "/extra", "offset": 999, "sha256": "xyz"})
        result = compare_sample(label(), found)
        self.assertEqual((result["tp"], result["fp"], result["fn"]), (1, 1, 0))
        self.assertEqual(result["duplicates"], 0)

    def test_unrelated_bundle_cannot_match_a_known_bundle(self):
        found = prediction()
        found["bundles"][0]["files"][0]["offset"] = 999
        result = compare_sample(label(), found)
        self.assertEqual((result["bundle_tp"], result["bundle_fp"], result["bundle_fn"]), (0, 1, 1))

    def test_incomplete_locale_metadata_is_not_expected(self):
        truth = label()
        truth["files"][0]["language"] = 1
        self.assertEqual(compare_sample(truth, prediction())["metadata_mismatches"], 0)

    def test_expected_duplicate_identities_are_not_reported_as_duplicates(self):
        truth = label()
        truth["files"].append(truth["files"][0])
        found = prediction()
        found["bundles"][0]["files"].append(found["bundles"][0]["files"][0])
        result = compare_sample(truth, found)
        self.assertEqual((result["tp"], result["duplicates"]), (2, 0))

    def test_empty_valid_bundle_still_makes_an_input_positive(self):
        truth = label()
        truth["files"] = []
        result = compare_sample(truth, prediction())
        self.assertEqual((result["file_tp"], result["file_fp"]), (1, 0))

    def test_wrong_locale_is_separate_from_detection(self):
        truth = label()
        truth["files"][0].update(language=1, territory=0)
        found = prediction()
        found["bundles"][0]["files"][0].update(language=2, territory=0)
        result = compare_sample(truth, found)
        self.assertEqual((result["tp"], result["fp"], result["metadata_mismatches"]), (1, 0, 1))

    def test_crash_and_timeout_are_separate(self):
        self.assertEqual(compare_sample(label(), {"status": "error"})["status"], "error")
        self.assertEqual(compare_sample(label(), {"status": "timeout"})["status"], "timeout")
        self.assertEqual(compare_sample(label(), None)["status"], "missing")

    def test_duplicate_response_rejected(self):
        with self.assertRaisesRegex(ValueError, "Repeated"):
            evaluate([label()], [prediction(), prediction()])

    def test_unknown_response_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown"):
            evaluate([], [prediction()])

    def test_unknown_bundle_count_not_scored(self):
        truth = label()
        truth["bundleStatus"] = "unknown"
        self.assertEqual(compare_sample(truth, prediction())["bundle_unscored"], 1)
