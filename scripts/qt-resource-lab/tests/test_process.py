from pathlib import Path
import sys
import tempfile
import unittest
from process import CommandFailure, run


class ProcessTests(unittest.TestCase):
    def test_cpu_and_stdin_are_accounted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "input"
            inputs.write_text("hello")
            result = run([sys.executable, "-c", "import sys; print(sys.stdin.read()); sum(i*i for i in range(500000))"],
                         root, root / "log", input_path=inputs)
            self.assertEqual(result["status"], "ok")
            self.assertGreater(result["cpuSeconds"], 0)
            self.assertGreater(result["peakBytes"], 0)
            self.assertIn("hello", (root / "log").read_text())

    def test_descendant_cpu_is_included(self):
        with tempfile.TemporaryDirectory() as directory:
            code = "import subprocess,sys; subprocess.run([sys.executable,'-c','sum(i*i for i in range(4000000))'],check=True)"
            result = run([sys.executable, "-c", code], directory, Path(directory) / "log")
            self.assertGreater(result["cpuSeconds"], 0.05)

    def test_timeout_kills_child_group(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(CommandFailure) as caught:
                run([sys.executable, "-c", "import time; time.sleep(10)"], directory,
                    Path(directory) / "log", timeout=0.05)
            self.assertEqual(caught.exception.result["status"], "timeout")

    def test_nonzero_retains_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(CommandFailure) as caught:
                run([sys.executable, "-c", "raise SystemExit(7)"], directory, Path(directory) / "log")
            self.assertEqual(caught.exception.result["exitCode"], 7)
