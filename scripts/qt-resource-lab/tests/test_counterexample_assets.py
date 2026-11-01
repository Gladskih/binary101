import hashlib
from pathlib import Path
import tempfile
import unittest
from counterexample_assets import assets, payload_decoy
from truth import negative_bytes


class CounterexampleAssetsTests(unittest.TestCase):
    def generate(self, family, seed=101, index=0):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        prefix, xml, expected = assets(root, {"family": family, "seed": seed}, index)
        return root, prefix, xml, expected

    def test_tiny_is_an_ordinary_one_byte_resource(self):
        root, prefix, xml, expected = self.generate("tiny")
        self.assertEqual(prefix, "/alignment")
        self.assertEqual((root / "asset0-0.bin").read_bytes(), b"x")
        self.assertEqual(expected, [{"path": "/alignment/tiny.txt", "sha256": hashlib.sha256(b"x").hexdigest(), "locale": "C"}])
        self.assertIn('alias="tiny.txt"', xml)

    def test_payload_decoy_has_a_separate_real_one_byte_manifest(self):
        root, _, _, expected = self.generate("payload-decoy")
        self.assertEqual((root / "asset0-0.bin").read_bytes(), b"x")
        self.assertEqual(len(expected), 1)
        self.assertEqual(expected[0]["sha256"], hashlib.sha256(b"x").hexdigest())

    def test_payload_decoy_is_retained_read_only_application_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            name = payload_decoy(root)
            source = (root / name).read_text(encoding="utf-8")
            self.assertIn("static const unsigned char application_fields[]", source)
            self.assertIn("return application_fields;", source)
            self.assertNotIn("qRegisterResourceData", source)
            image = root / "sample"
            image.write_bytes(b"prefix\0\0\0\1ytail")
            evidence = negative_bytes(root, image, {"negative": True, "sourceFiles": [name]})
            self.assertEqual((evidence[0]["offset"], evidence[0]["size"]), (6, 5))

    def test_empty_file_remains_a_positive_resource(self):
        root, _, _, expected = self.generate("empty-file")
        self.assertEqual((root / "asset0-0.bin").read_bytes(), b"")
        self.assertEqual(len(expected), 1)
        self.assertEqual(expected[0]["sha256"], hashlib.sha256(b"").hexdigest())

    def test_sizes_cover_padding_boundaries_with_distinct_content(self):
        root, _, _, expected = self.generate("sizes")
        # Include both sides of common 2/4/8/16-byte and page boundaries.
        lengths = sorted(path.stat().st_size for path in root.glob("asset*.bin"))
        self.assertEqual(lengths, [0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33,
                                   63, 64, 65, 127, 128, 129, 255, 256, 257, 4095, 4096, 4097])
        self.assertEqual(len({entry["sha256"] for entry in expected}), len(expected))

    def test_metadata_text_must_not_be_filtered_as_compiler_metadata(self):
        root, _, _, expected = self.generate("metadata-text")
        content = b"".join(path.read_bytes() for path in sorted(root.glob("asset*.bin")))
        self.assertIn(b"GCC: ", content)
        self.assertIn(b"GNU\0", content)
        self.assertIn(b"\0\0\0GCC: ", content)
        self.assertGreaterEqual(len(expected), 3)

    def test_opaque_bytes_do_not_depend_on_file_extensions(self):
        root, _, xml, expected = self.generate("opaque")
        self.assertIn('alias="not-an-image.png"', xml)
        self.assertEqual((root / "asset0-0.bin").read_bytes(), bytes(range(256)))
        self.assertEqual(len(expected), 2)

    def test_small_sets_share_layout_without_sharing_payload(self):
        first, _, _, expected_first = self.generate("small-sets", index=0)
        second, _, _, expected_second = self.generate("small-sets", index=1)
        self.assertEqual([path.stat().st_size for path in sorted(first.glob("asset*.bin"))],
                         [path.stat().st_size for path in sorted(second.glob("asset*.bin"))])
        self.assertNotEqual(expected_first[0]["sha256"], expected_second[0]["sha256"])

    def test_compressed_sizes_use_the_same_diverse_payload_contract(self):
        root, _, _, expected = self.generate("compressed-sizes")
        self.assertEqual(len(expected), 25)
        self.assertEqual(max(path.stat().st_size for path in root.glob("asset*.bin")), 4097)

    def test_generation_is_reproducible_but_seed_changes_binary_content(self):
        _, _, _, first = self.generate("sizes")
        _, _, _, second = self.generate("sizes")
        _, _, _, changed = self.generate("sizes", seed=102)
        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)

    def test_unknown_family_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Unknown counterexample"):
            self.generate("unexpected")
