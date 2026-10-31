from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch
from controller import valid_cached, valid_pilot_identity, valid_published, export_corpus
from model import digest, write_json
from report import report


class ControllerTests(unittest.TestCase):
    def test_changed_compiler_cannot_resume_old_binary(self):
        saved = {"recipeSha256": "recipe", "kitSha256": "kit", "status": "built", "labels": [],
                 "sdk": {"compilerVersions": {"gcc": "old"}}}
        with patch("controller.recipe_hash", return_value="recipe"):
            self.assertFalse(valid_cached(saved, {"fingerprint": "kit", "compilerVersions": {"gcc": "new"}}))

    def test_stale_recipe_cannot_resume(self):
        saved = {"recipeSha256": "stale", "kitSha256": "kit", "status": "built", "labels": []}
        with patch("controller.recipe_hash", return_value="new"):
            self.assertFalse(valid_cached(saved, {"fingerprint": "kit"}))

    def test_changed_input_cannot_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample"
            path.write_bytes(b"original")
            row = {"path": str(path), "sha256": digest(path)}
            self.assertTrue(valid_published(row))
            path.write_bytes(b"changed")
            self.assertFalse(valid_published(row))

    def test_stale_gate_cannot_authorize(self):
        record = {"passed": True, "sdkIds": ["sdk"], "recipeSha256": "old", "sdkFingerprints": {"sdk": "pin"}}
        with patch("controller.recipe_hash", return_value="new"):
            self.assertFalse(valid_pilot_identity(record, [{"id": "sdk", "fingerprint": "pin"}]))

    def test_old_recipe_labels_are_not_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_json(root / "jobs/old/result.json", {"recipeSha256": "old", "labels": [{"id": "must-not-export"}]})
            with patch("controller.recipe_hash", return_value="new"):
                export_corpus(root)
            self.assertEqual((root / "labels.jsonl").read_text(), "")

    def test_unknown_inventory_is_visible_but_not_negative(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = {"id": "unknown", "path": "unused", "sha256": "hash", "family": "shipping", "status": "unknown", "format": "PE", "variant": "shipping", "split": "holdout"}
            (root / "labels.jsonl").write_text(json.dumps(row) + "\n")
            write_json(root / "evaluation.json", [{"id": "unknown", "status": "unknown", "fp": 0, "fn": 0,
                                                  "content_mismatches": 0}])
            result = report(root)
            self.assertEqual(result["truthCounts"], {"unknown": 1})
            self.assertEqual(result["totals"]["fp"], 0)
            self.assertEqual(result["denominators"]["negativeInputs"], 0)
