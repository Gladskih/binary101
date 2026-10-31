from pathlib import Path
import tempfile
import unittest
from model import HOLDOUT, digest, pilot_schedule, read_jsonl, schedule, write_json
from controller import linux_path, windows_path


class ModelTests(unittest.TestCase):
    def test_deterministic_family_split(self):
        rows = schedule([{"id": "sdk"}], 101)
        self.assertEqual(rows, schedule([{"id": "sdk"}], 101))
        self.assertNotEqual(rows, schedule([{"id": "sdk"}], 102))
        self.assertEqual({r["family"] for r in rows if r["split"] == "holdout"}, HOLDOUT)
        self.assertEqual(len({r["id"] for r in rows}), len(rows))

    def test_unavailable_compression_is_not_scheduled(self):
        rows = schedule([{"id": "sdk", "compression": {"zstd": {"supported": False}}}], 101)
        self.assertNotIn("zstd", {row["family"] for row in rows})
        self.assertIn("compressed", {row["family"] for row in rows})

    def test_pilot_contains_both_targets_and_labels(self):
        rows = pilot_schedule(schedule([{"id": "one"}, {"id": "two"}], 101))
        self.assertGreaterEqual(len(rows), 8)
        self.assertEqual({r["target"] for r in rows}, {"exe", "library"})
        self.assertIn("basic", {r["family"] for r in rows})
        self.assertIn("bad-hash", {r["family"] for r in rows})

    def test_atomic_json_and_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "record.json"
            write_json(path, {"text": "λ"})
            self.assertEqual(read_jsonl_json(path), {"text": "λ"})
            self.assertEqual(len(digest(path)), 64)
            self.assertFalse(path.with_suffix(".json.tmp").exists())

    def test_path_translation(self):
        self.assertEqual(windows_path("/mnt/c/Users/file"), "C:/Users/file")
        self.assertEqual(windows_path("C:/file"), "C:/file")


def read_jsonl_json(path):
    import json
    return json.loads(path.read_text(encoding="utf-8"))
