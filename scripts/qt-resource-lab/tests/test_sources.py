from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import struct
from sources import disable_registration, negative_source
from truth import arrays_from_cpp, confirm_expected, select_variants, negative_bytes
from scan import validate_reply


class SourcesTests(unittest.TestCase):
    def test_bad_size_corrupts_embedded_payload_not_only_container_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # qres v1: data at 20, names at 25, tree at 33; one-byte payload.
            blob = struct.pack(">4sIIII", b"qres", 1, 33, 20, 25) + b"\0\0\0\1x" + bytes(8 + 28)
            (root / "resource.rcc").write_bytes(blob)
            with patch("sources.negative_tables", return_value="tables.cpp"):
                negative_source(root, {"family": "bad-size"}, [{"qres": "resource.rcc"}])
            declaration = (root / "decoy.cpp").read_text(encoding="utf-8")
            numbers = declaration.split(" = {", 1)[1].split("};", 1)[0]
            retained = bytes(int(number) for number in numbers.split(","))
            start = retained.index(b"qres")
            # First qres occurs in the string decoy; inspect the actual header after it.
            start = retained.index(b"qres", start + 4)
            self.assertEqual(retained[start + 20:start + 25], b"\xff" * 5)
            self.assertGreater(struct.unpack_from(">I", retained, start + 12)[0], len(blob))

    def test_missing_compiled_decoy_prevents_verified_negative_label(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "decoy.cpp").write_text("static const volatile unsigned char decoy[] = {1,2,3};")
            image = root / "sample.exe"
            image.write_bytes(b"unrelated final bytes")
            with self.assertRaisesRegex(ValueError, "eliminated"):
                negative_bytes(root, image, {"negative": True, "sourceFiles": ["decoy.cpp"]})
            image.write_bytes(b"prefix\x01\x02\x03tail")
            self.assertEqual(negative_bytes(root, image, {"negative": True, "sourceFiles": ["decoy.cpp"]})[0]["offset"], 6)

    def test_locale_fallback_does_not_invent_entries(self):
        prepared = {"resources": [{"expected": [{"path": "/a", "locale": "C"}, {"path": "/a", "locale": "de_DE"}]}]}
        files = [{"path": "/a", "locale": locale, "offset": 100, "sha256": "same"}
                 for locale in ("C", "de_DE", "ru_RU")]
        self.assertEqual([r["locale"] for r in select_variants(files, prepared)], ["C", "de_DE"])

    def test_unknown_initializer_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "qrc.cpp"
            path.write_text("unrecognized producer")
            with self.assertRaisesRegex(ValueError, "Unrecognized"):
                disable_registration(path)

    def test_disable_preserves_arrays_and_removes_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "qrc.cpp"
            path.write_text("initializer() { QT_RCC_MANGLE_NAMESPACE(qInitResources)(); }\n~initializer() { cleanup(); }")
            disable_registration(path)
            self.assertIn("initializer() {}", path.read_text())
            self.assertIn("lab_unused_struct", path.read_text())

    def test_arrays_are_producer_bytes_not_parser_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "qrc.cpp"
            path.write_text("\n".join(f"static const unsigned char qt_resource_{name}[] = {{0x01,0xff}};" for name in ("struct", "name", "data")))
            self.assertEqual(arrays_from_cpp(path)["data"], b"\x01\xff")
            path.write_text("missing")
            with self.assertRaises(ValueError):
                arrays_from_cpp(path)

    def test_expected_content_disagreement(self):
        with self.assertRaisesRegex(ValueError, "disagreement"):
            confirm_expected({"prefix": "/lab", "expected": [{"path": "/lab/a", "sha256": "a"}]}, [])

    def test_reply_validation(self):
        self.assertEqual(validate_reply({"status": "ok", "bundles": []})["status"], "ok")
        with self.assertRaises(ValueError):
            validate_reply({"status": "ok"})
        with self.assertRaises(ValueError):
            validate_reply({"status": "ok", "bundles": [{"files": [{}]}]})
        with self.assertRaises(ValueError):
            validate_reply({"status": "silent"})
