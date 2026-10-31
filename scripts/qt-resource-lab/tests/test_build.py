from pathlib import Path
import tempfile
import unittest
from build import project, target_path
from sdk import environment_for
from controller import stop_reason
import time


class BuildTests(unittest.TestCase):
    def test_qmake_cannot_strip_reference_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project(root, {"clang": "clang++", "format": "PE"},
                    {"compiler": "clang", "profile": "LTO", "target": "library"},
                    {"negative": True, "sourceFiles": ["decoy.cpp"]})
            text = (root / "sample.pro").read_text()
            self.assertIn("QMAKE_LFLAGS_RELEASE =\n", text)
            self.assertIn("-fuse-ld=lld", text)
            self.assertIn("QMAKE_CXXFLAGS -= -fno-keep-inline-dllexport", text)
            self.assertIn("DEFINES += LAB_DECOY", text)

    def test_target_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "release").mkdir()
            expected = root / "release/sample.exe"
            expected.write_bytes(b"exe")
            self.assertEqual(target_path(root, {"format": "PE"}, {"target": "exe"}), expected)

    def test_environment_does_not_persist_secrets(self):
        self.assertEqual(set(environment_for("C:/msys64/ucrt64/bin/qmake.exe")),
                         {"PATH", "SOURCE_DATE_EPOCH", "QT_QPA_PLATFORM", "LC_ALL"})

    def test_systematic_failures_stop_submission(self):
        records = [{"status": "failed"}] * 3
        self.assertEqual(stop_reason(records, time.monotonic(), 4, time.monotonic() + 100, "completed"),
                         "systematic-failures")

    def test_cpu_gate_stops_wait_bound_run(self):
        records = [{"status": "built", "cpuSeconds": 0}] * 16
        self.assertEqual(stop_reason(records, time.monotonic() - 30, 4, time.monotonic() + 100, "completed"),
                         "not-cpu-bound")
