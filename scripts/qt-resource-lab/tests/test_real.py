from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch
from model import digest, write_json
from real import real_corpus, read_real_inputs, registered_label, validate_input


def oracle_files(command, _root, log, environment):
    item = {"module": command[1], "path": ":/sample", "relative": 24, "algorithm": 1}
    write_json(log, {"files": [{**item, "module": "other.rcc"}, item, item]})
    return {"command": command, "environment": environment}


class RealCorpusTests(unittest.TestCase):
    def test_empty_explicit_inventory_does_not_discover_sdk_or_applications(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_json(root / "real-inputs.json", [])
            with patch("real.discover", side_effect=AssertionError("No implicit discovery")):
                self.assertEqual(real_corpus(root)["realFiles"], 0)

    def test_malformed_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real-inputs.json").write_text("[", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                read_real_inputs(root)

    def test_only_explicit_inputs_are_imported_without_sdk_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.dll"
            source.write_bytes(b"explicit input")
            write_json(root / "real-inputs.json", [{"path": str(source)}])
            with patch("real.discover", side_effect=AssertionError("No SDK needed")):
                result = real_corpus(root)
            self.assertEqual(result["realFiles"], 1)
            self.assertEqual(result["unknownModules"], 1)
            labels = json.loads((root / "real-labels.json").read_text())
            self.assertEqual(labels[0]["sha256"], digest(source))
            self.assertEqual(labels[0]["status"], "unknown")

    def test_missing_manifest_does_not_inspect_installed_applications(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("real.discover", side_effect=AssertionError("No implicit discovery")):
                with self.assertRaises(FileNotFoundError):
                    real_corpus(Path(directory))

    def test_manifest_requires_an_array(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_json(root / "real-inputs.json", {})
            with self.assertRaisesRegex(ValueError, "array"):
                read_real_inputs(root)

    def test_invalid_entries_are_rejected(self):
        for entry in (None, {}, {"path": ""}, {"path": 1}):
            with self.subTest(entry=entry), self.assertRaisesRegex(ValueError, "path"):
                validate_input(entry, Path("."))

    def test_missing_input_is_not_silently_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                validate_input({"path": "missing.dll"}, Path(directory))

    def test_relative_input_and_matching_pin_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.dll"
            source.write_bytes(b"explicit input")
            entry = validate_input({"path": source.name, "sha256": digest(source)}, root)
            self.assertEqual(entry["path"], source.resolve())
            self.assertEqual(entry["registrations"], [])

    def test_wrong_pin_and_unpinned_registrations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input.dll").write_bytes(b"explicit input")
            with self.assertRaisesRegex(ValueError, "SHA256"):
                validate_input({"path": "input.dll", "sha256": "wrong"}, root)
            with self.assertRaisesRegex(ValueError, "pinned"):
                validate_input({"path": "input.dll", "registrations": [[0, 1, 2]]}, root)

    def test_invalid_registration_shapes_and_rvas_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input.dll").write_bytes(b"explicit input")
            for registrations in (None, "", [0], [[0]], [[-1, 0, 0]],
                                  [[0, 0, 1 << 32]], [[True, 0, 0]], [[0.5, 0, 0]]):
                with self.subTest(registrations=registrations), self.assertRaisesRegex(ValueError, "RVAs"):
                    validate_input({"path": "input.dll", "registrations": registrations}, root)

    def test_explicit_registered_inputs_reuse_one_consumer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.dll"
            source.write_bytes(b"explicit input")
            registrations = [[0, 1, 0xffffffff]]
            write_json(root / "real-inputs.json", [{"path": source.name,
                       "sha256": digest(source), "registrations": registrations}])
            sdk = {"major": 5, "linkage": "shared"}
            label = {"status": "partial", "files": []}
            with patch("real.discover", return_value={"sdks": [sdk]}), \
                    patch("real.consumer", return_value="consumer") as consumer, \
                    patch("real.registered_label", return_value=label) as registered, \
                    patch("controller.export_corpus"):
                result = real_corpus(root)
            consumer.assert_called_once_with(root, sdk)
            registered.assert_called_once_with(root, sdk, "consumer", source.resolve(), registrations)
            self.assertEqual(result["realFiles"], 1)
            self.assertEqual(result["unknownModules"], 0)

    def test_registered_inputs_require_a_shared_sdk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.dll"
            source.write_bytes(b"explicit input")
            write_json(root / "real-inputs.json", [{"path": source.name,
                       "sha256": digest(source), "registrations": [[0, 1, 2]]}])
            with patch("real.discover", return_value={"sdks": [{"major": 6, "linkage": "shared"}]}):
                with self.assertRaisesRegex(ValueError, "Qt 5"):
                    real_corpus(root)

    def test_registered_label_uses_explicit_image_and_registration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.dll"
            source.write_bytes(b"explicit input")
            with patch("real.file_offset", side_effect=lambda _image, address: address), \
                    patch("real.container_for", return_value=b"qres") as container, \
                    patch("real.run", side_effect=oracle_files):
                label = registered_label(root, {"environment": {}}, "consumer", source, [[10, 20, 30]])
            container.assert_called_once_with(source, [10, 20, 30], [10, 20, 30])
            self.assertEqual(label["status"], "partial")
            self.assertEqual(label["bundleStatus"], "verified")
            self.assertEqual(label["files"][0]["offset"], 34)
            self.assertEqual(len(label["files"]), 1)

    def test_registered_label_reports_oracle_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.dll"
            source.write_bytes(b"explicit input")
            with patch("real.file_offset", side_effect=lambda _image, address: address), \
                    patch("real.container_for", return_value=b"qres"), \
                    patch("real.run", side_effect=lambda _cmd, _root, log, **_kw: write_json(log, {"error": "bad"})):
                with self.assertRaisesRegex(ValueError, "bad"):
                    registered_label(root, {"environment": {}}, "consumer", source, [[10, 20, 30]])
