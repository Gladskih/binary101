from struct import pack
from zlib import crc32

from PIL import ExifTags, Image
from PIL.TiffImagePlugin import IFDRational


def rar_vint(value):
    encoded = bytearray()
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def rar_header(body):
    fields = rar_vint(len(body)) + body
    return pack("<I", crc32(fields)) + fields


def stored_rar_entry(path):
    # RAR 5 signature and the main/file/end record layouts from the format notes.
    # https://www.rarlab.com/technote.htm
    data = path.read_bytes()
    name = path.name.encode("utf-8")
    main_header = rar_header(bytes((1, 0, 0)))
    # Type 2, data-area flag, size, file data CRC flag, unpacked size, DOS attributes.
    file_fields = bytes((2, 2)) + rar_vint(len(data)) + bytes((4,))
    file_fields += rar_vint(len(data)) + bytes((32,)) + pack("<I", crc32(data))
    # Store method, Windows host OS, then UTF-8 name.
    file_fields += bytes((0, 0)) + rar_vint(len(name)) + name
    end_header = rar_header(bytes((5, 0, 0)))
    return bytes.fromhex("526172211a070100") + main_header + rar_header(file_fields) + data + end_header


def build_jpeg(output, payload):
    with Image.open(output / "test-pattern.png") as image:
        exif = image.getexif()
        tags = ExifTags.Base
        exif[tags.Make] = "Binary101"
        exif[tags.Model] = "Generated test pattern"
        exif[tags.Software] = "Binary101 gallery generator"
        exif[tags.Orientation] = 1
        exif[ExifTags.IFD.Exif] = {
            tags.DateTimeOriginal: "2026:01:01 12:00:00",
            tags.ExposureTime: IFDRational(1, 125),
            tags.FNumber: IFDRational(28, 10),
            tags.FocalLength: IFDRational(35),
            tags.ISOSpeedRatings: 100,
        }
        jpeg = output / "test-pattern.jpg"
        image.save(jpeg, quality=90, exif=exif)
    (output / "test-pattern-rar.jpg").write_bytes(jpeg.read_bytes() + stored_rar_entry(payload))
