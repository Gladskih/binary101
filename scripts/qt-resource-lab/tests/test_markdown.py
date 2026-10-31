from pathlib import Path
import tempfile
import unittest
from markdown import write_markdown
from model import write_json


class MarkdownTests(unittest.TestCase):
    def test_report_does_not_claim_unobserved_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "doctor.json", {"sdks": [{"id": "kit", "qtLto": "not-established"}]})
            write_json(root / "unsupported-cells.json", [{"sdk": "kit", "algorithm": "zstd"}])
            summary = {"buildRuns": {}, "totals": {}, "denominators": {"evaluatedCompleteInputs": 0,
                       "positiveInputs": 0, "negativeInputs": 0}, "samples": 1, "uniqueSha256": 1,
                       "truthCounts": {"unknown": 1}, "scannerStatuses": {"error": 1}}
            write_markdown(root, summary)
            text = (root / "report.md").read_text(encoding="utf-8")
            self.assertIn("not-run", text)
            self.assertIn("not-established", text)
            self.assertIn("zero-FP guarantee", text)
            self.assertIn("Unsupported", text)
