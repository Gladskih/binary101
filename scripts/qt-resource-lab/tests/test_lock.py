from pathlib import Path
import tempfile
import unittest
from lock import corpus_lock


class LockTests(unittest.TestCase):
    def test_second_writer_is_rejected_and_release_is_automatic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with corpus_lock(root):
                with self.assertRaisesRegex(RuntimeError, "Another"):
                    with corpus_lock(root):
                        self.fail("Second writer entered")
            with corpus_lock(root):
                self.assertTrue((root / ".writer.lock").exists())
