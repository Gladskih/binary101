from pathlib import Path
import struct
import tempfile
import unittest
from image import file_offset, image_regions, symbol_count


def pe_bytes():
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 70, 1)
    struct.pack_into("<I", data, 80, 7)
    struct.pack_into("<H", data, 84, 240)
    struct.pack_into("<III", data, 64 + 24 + 240 + 12, 4096, 512, 512)
    return data


class ImageTests(unittest.TestCase):
    def test_pe_mapping_and_symbols(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample"
            path.write_bytes(pe_bytes())
            self.assertEqual(image_regions(path), [(4096, 512, 512)])
            self.assertEqual(file_offset(path, 4100), 516)
            self.assertEqual(symbol_count(path), 7)
            with self.assertRaises(ValueError):
                file_offset(path, 0)

    def test_invalid_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample"
            path.write_bytes(b"not a binary")
            with self.assertRaises(ValueError):
                image_regions(path)

    def test_elf_uses_load_bias(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample"
            data = bytearray(1024)
            data[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<Q", data, 32, 64)
            struct.pack_into("<HH", data, 54, 56, 1)
            struct.pack_into("<I", data, 64, 1)
            struct.pack_into("<QQ", data, 72, 128, 0x400000)
            struct.pack_into("<Q", data, 96, 512)
            path.write_bytes(data)
            self.assertEqual(file_offset(path, 4), 132)
