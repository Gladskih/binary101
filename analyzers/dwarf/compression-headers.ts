"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { DwarfSectionInput } from "./types.js";

export type DwarfSectionCompression =
  | { kind: "gnu-zlib" }
  | { kind: "elf"; elfClass: "elf32" | "elf64"; byteOrder: "big" | "little" };

export type DwarfCompressionPayload = {
  name: string;
  offset: number;
  size: number;
  uncompressedSize: number;
};

const GNU_HEADER = {
  byteLength: 12,
  magic: 0x5a4c4942,
  sizeOffset: 4
} as const;

// ELF gABI, "Compressed Sections", defines Elf32_Chdr/Elf64_Chdr and
// ELFCOMPRESS_ZLIB. GNU .zdebug uses "ZLIB" plus an 8-byte big-endian size:
// https://www.sco.com/developers/gabi/latest/ch4.sheader.html
// https://gnu.googlesource.com/binutils-gdb/+/refs/heads/gdb-15-branch/bfd/compress.c
const ELF_COMPRESSION = {
  typeOffset: 0,
  zlib: 1,
  zstd: 2,
  elf32: { headerBytes: 12, sizeOffset: 4 },
  elf64: { headerBytes: 24, reservedOffset: 4, sizeOffset: 8 }
} as const;

export const canonicalDwarfSectionName = (name: string): string =>
  name.startsWith(".zdebug_") ? `.debug_${name.slice(".zdebug_".length)}` : name;

const safeSize = (value: bigint, label: string, issues: string[]): number | null => {
  const size = Number(value);
  if (!Number.isSafeInteger(size)) {
    issues.push(`${label} ${value.toString()} is not a safe byte length.`);
    return null;
  }
  return size;
};

const readHeader = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  headerBytes: number,
  label: string,
  issues: string[]
): Promise<DataView | null> => {
  if (!Number.isSafeInteger(section.offset) || !Number.isSafeInteger(section.size) ||
      section.offset < 0 || section.size < 0) {
    issues.push(`${label} range is not a safe non-negative integer range.`);
    return null;
  }
  const view = await reader.read(section.offset, Math.min(headerBytes, section.size));
  if (view.byteLength === headerBytes) return view;
  issues.push(`${label} is truncated (${view.byteLength} of ${headerBytes} bytes readable).`);
  return null;
};

const readGnuPayload = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  issues: string[]
): Promise<DwarfCompressionPayload | null> => {
  const view = await readHeader(
    reader,
    section,
    GNU_HEADER.byteLength,
    `${section.name} GNU compression header`,
    issues
  );
  if (!view) return null;
  if (view.getUint32(0, false) !== GNU_HEADER.magic) {
    issues.push(`${section.name}: invalid GNU compressed-section ZLIB signature.`);
    return null;
  }
  const uncompressedSize = safeSize(
    view.getBigUint64(GNU_HEADER.sizeOffset, false),
    `${section.name} uncompressed size`,
    issues
  );
  return uncompressedSize == null ? null : {
    name: canonicalDwarfSectionName(section.name),
    offset: section.offset + GNU_HEADER.byteLength,
    size: section.size - GNU_HEADER.byteLength,
    uncompressedSize
  };
};

const elfCompressionLayout = (elfClass: "elf32" | "elf64") =>
  elfClass === "elf64" ? ELF_COMPRESSION.elf64 : ELF_COMPRESSION.elf32;

const readElfPayload = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  compression: Extract<DwarfSectionCompression, { kind: "elf" }>,
  issues: string[]
): Promise<DwarfCompressionPayload | null> => {
  const layout = elfCompressionLayout(compression.elfClass);
  const littleEndian = compression.byteOrder === "little";
  const view = await readHeader(
    reader,
    section,
    layout.headerBytes,
    `${section.name} ELF compression header`,
    issues
  );
  if (!view) return null;
  const type = view.getUint32(ELF_COMPRESSION.typeOffset, littleEndian);
  if (type !== ELF_COMPRESSION.zlib) {
    issues.push(
      `${section.name}: unsupported ELF compression ` +
      `${type === ELF_COMPRESSION.zstd ? "Zstandard" : `type ${type}`}.`
    );
    return null;
  }
  if (compression.elfClass === "elf64" &&
      view.getUint32(ELF_COMPRESSION.elf64.reservedOffset, littleEndian) !== 0) {
    issues.push(`${section.name}: ELF64 compression header reserved field is non-zero.`);
    return null;
  }
  const sizeValue = compression.elfClass === "elf64"
    ? view.getBigUint64(layout.sizeOffset, littleEndian)
    : BigInt(view.getUint32(layout.sizeOffset, littleEndian));
  const uncompressedSize = safeSize(sizeValue, `${section.name} uncompressed size`, issues);
  return uncompressedSize == null ? null : {
    name: section.name,
    offset: section.offset + layout.headerBytes,
    size: section.size - layout.headerBytes,
    uncompressedSize
  };
};

export const readDwarfCompressionPayload = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  compression: DwarfSectionCompression,
  issues: string[]
): Promise<DwarfCompressionPayload | null> => compression.kind === "gnu-zlib"
  ? readGnuPayload(reader, section, issues)
  : readElfPayload(reader, section, compression, issues);
