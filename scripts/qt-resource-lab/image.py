"""Independent load-image mapping for oracle pointers and stripping invariants."""
import struct
from pathlib import Path


def image_regions(path):
    with Path(path).open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64:
            raise ValueError("Truncated image header")
        if header[:2] == b"MZ":
            return pe_regions(stream, header)
        if header[:6] == b"\x7fELF\x02\x01":
            return elf_regions(stream, header)
    raise ValueError("Oracle mapper supports PE and little-endian ELF64")


def pe_regions(stream, header):
    position = struct.unpack_from("<I", header, 60)[0]
    require_file_range(stream, position, 24)
    stream.seek(position)
    signature = stream.read(24)
    if signature[:4] != b"PE\0\0":
        raise ValueError("Missing PE signature")
    count = struct.unpack_from("<H", signature, 6)[0]
    width = struct.unpack_from("<H", signature, 20)[0]
    require_file_range(stream, position + 24, width + count * 40)
    optional = stream.read(width)
    if len(optional) < 64:
        raise ValueError("Short PE optional header")
    sections = [stream.read(40) for _ in range(count)]
    regions = [(struct.unpack_from("<I", section, 12)[0], *struct.unpack_from("<II", section, 16)[::-1])
               for section in sections if struct.unpack_from("<I", section, 16)[0]]
    validate_regions(stream, regions)
    return regions


def elf_regions(stream, header):
    offset = struct.unpack_from("<Q", header, 32)[0]
    width, count = struct.unpack_from("<HH", header, 54)
    if width < 56 or count > 65535:
        raise ValueError("Invalid ELF program header dimensions")
    require_file_range(stream, offset, width * count)
    regions = []
    for index in range(count):
        stream.seek(offset + index * width)
        record = stream.read(56)
        if len(record) != 56:
            raise ValueError("Truncated ELF program header")
        if struct.unpack_from("<I", record)[0] == 1:
            file_offset, address = struct.unpack_from("<QQ", record, 8)
            regions.append((address, file_offset, struct.unpack_from("<Q", record, 32)[0]))
    if not regions:
        raise ValueError("ELF contains no file-backed PT_LOAD")
    validate_regions(stream, regions)
    base = min(address for address, _, _ in regions)
    return [(address - base, offset, size) for address, offset, size in regions]


def validate_regions(stream, regions):
    for _, offset, size in regions:
        require_file_range(stream, offset, size)


def file_offset(path, relative):
    matches = [offset + relative - address for address, offset, size in image_regions(path)
               if address <= relative < address + size]
    if len(matches) != 1:
        raise ValueError(f"Oracle pointer {relative:#x} has no unique file backing")
    return matches[0]


def require_file_range(stream, offset, size):
    position = stream.tell()
    stream.seek(0, 2)
    file_size = stream.tell()
    stream.seek(position)
    if offset < 0 or size < 0 or offset + size > file_size:
        raise ValueError("Image range exceeds file")


def symbol_count(path):
    with Path(path).open("rb") as stream:
        header = stream.read(64)
        if header[:2] == b"MZ":
            stream.seek(struct.unpack_from("<I", header, 60)[0] + 16)
            return struct.unpack("<I", stream.read(4))[0]
        table = struct.unpack_from("<Q", header, 40)[0]
        width, count = struct.unpack_from("<HH", header, 58)
        for index in range(count):
            stream.seek(table + index * width)
            section = stream.read(64)
            if len(section) == 64 and struct.unpack_from("<I", section, 4)[0] == 2:
                size = struct.unpack_from("<Q", section, 32)[0]
                entry_size = struct.unpack_from("<Q", section, 56)[0]
                return size // entry_size if entry_size else 0
    return 0
