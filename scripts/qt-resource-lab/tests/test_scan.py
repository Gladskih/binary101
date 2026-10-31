from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scan import fingerprint, parse_reply


class ScanTests(unittest.TestCase):
    def test_untracked_detector_change_invalidates_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "analyzers").mkdir()
            detector = root / "analyzers/candidate.ts"
            detector.write_text("version one")
            with patch("scan.REPO", root), patch("scan.subprocess.check_output", return_value=b"head"):
                before = fingerprint(["scanner"])
                detector.write_text("version two")
                self.assertNotEqual(before, fingerprint(["scanner"]))
                self.assertNotEqual(fingerprint(["scanner"], "one"), fingerprint(["scanner"], "two"))

    def test_multiple_or_mismatched_replies_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reply"
            path.write_text('{"id":"wrong","status":"error"}\n')
            with self.assertRaisesRegex(ValueError, "matching"):
                parse_reply(path, "expected")
            path.write_text('{"id":"expected","status":"error"}\n' * 2)
            with self.assertRaisesRegex(ValueError, "exactly one"):
                parse_reply(path, "expected")
