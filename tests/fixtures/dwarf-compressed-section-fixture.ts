"use strict";

import { deflateSync } from "node:zlib";
import type { DwarfSectionCompression } from "../../analyzers/dwarf/compression-headers.js";
import type { DwarfSectionCandidate } from "../../analyzers/dwarf/compressed-sections.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  concatenateBytes,
  encodeBigEndianUnsigned,
  encodeUnsigned
} from "./dwarf-fixture-encoding.js";
import { createDwarf4SectionsFixture } from "./dwarf-sections-fixture.js";

// Independent oracle for ELF gABI compression headers and GNU .zdebug framing:
// https://www.sco.com/developers/gabi/latest/ch4.sheader.html
// https://gnu.googlesource.com/binutils-gdb/+/refs/heads/gdb-15-branch/bfd/compress.c
export const TEST_DWARF_COMPRESSION = {
  maximumDecompressedBytes: 256 * 1024 * 1024,
  gnu: { headerBytes: 12, magic: 0x5a4c4942 },
  elf: {
    zlibType: 1,
    zstdType: 2,
    alignment: 1,
    elf32HeaderBytes: 12,
    elf64HeaderBytes: 24
  }
} as const;

export type TestDwarfCompressionFormat =
  | "elf32-big-zlib"
  | "elf32-little-zlib"
  | "elf64-little-zlib"
  | "gnu-zlib";

const endianUnsigned = (
  value: bigint | number,
  byteCount: number,
  byteOrder: "big" | "little"
): number[] => byteOrder === "little"
  ? encodeUnsigned(value, byteCount)
  : encodeBigEndianUnsigned(value, byteCount);

const compressedBytes = (bytes: Uint8Array): number[] => [...deflateSync(bytes)];

export const encodeGnuCompressedSection = (
  bytes: Uint8Array,
  declaredSize: bigint = BigInt(bytes.length),
  magic: number = TEST_DWARF_COMPRESSION.gnu.magic
): number[] => concatenateBytes(
  encodeBigEndianUnsigned(magic, Uint32Array.BYTES_PER_ELEMENT),
  encodeBigEndianUnsigned(declaredSize, BigUint64Array.BYTES_PER_ELEMENT),
  compressedBytes(bytes)
);

export const encodeElfCompressedSection = (
  bytes: Uint8Array,
  elfClass: "elf32" | "elf64",
  byteOrder: "big" | "little",
  declaredSize: bigint = BigInt(bytes.length),
  compressionType: number = TEST_DWARF_COMPRESSION.elf.zlibType,
  reserved: number = 0
): number[] => {
  const word = (value: bigint | number): number[] =>
    endianUnsigned(value, Uint32Array.BYTES_PER_ELEMENT, byteOrder);
  const extendedWord = (value: bigint | number): number[] =>
    endianUnsigned(value, BigUint64Array.BYTES_PER_ELEMENT, byteOrder);
  const header = elfClass === "elf64"
    ? concatenateBytes(
      word(compressionType),
      word(reserved),
      extendedWord(declaredSize),
      extendedWord(TEST_DWARF_COMPRESSION.elf.alignment)
    )
    : concatenateBytes(
      word(compressionType),
      word(declaredSize),
      word(TEST_DWARF_COMPRESSION.elf.alignment)
    );
  return concatenateBytes(header, compressedBytes(bytes));
};

const compressionFor = (format: TestDwarfCompressionFormat): DwarfSectionCompression => {
  if (format === "gnu-zlib") return { kind: "gnu-zlib" };
  if (format === "elf32-big-zlib") {
    return { kind: "elf", elfClass: "elf32", byteOrder: "big" };
  }
  return {
    kind: "elf",
    elfClass: format === "elf64-little-zlib" ? "elf64" : "elf32",
    byteOrder: "little"
  };
};

const encodeSection = (
  bytes: Uint8Array,
  format: TestDwarfCompressionFormat
): number[] => {
  if (format === "gnu-zlib") return encodeGnuCompressedSection(bytes);
  const compression = compressionFor(format);
  if (compression.kind !== "elf") return [];
  return encodeElfCompressedSection(bytes, compression.elfClass, compression.byteOrder);
};

const compressedName = (name: string, format: TestDwarfCompressionFormat): string =>
  format === "gnu-zlib" ? name.replace(".debug_", ".zdebug_") : name;

export const createCompressedDwarfSectionsFixture = (
  format: TestDwarfCompressionFormat
): { file: MockFile; candidates: DwarfSectionCandidate[] } => {
  const source = createDwarf4SectionsFixture();
  const parts: number[][] = [];
  const candidates: DwarfSectionCandidate[] = [];
  let offset = 0;
  source.sections.filter(section => section.size > 0).forEach(section => {
    const decoded = source.file.data.subarray(section.offset, section.offset + section.size);
    const encoded = encodeSection(decoded, format);
    const name = compressedName(section.name, format);
    candidates.push({
      section: { name, offset, size: encoded.length, compressed: true },
      compression: compressionFor(format)
    });
    parts.push(encoded);
    offset += encoded.length;
  });
  return {
    file: new MockFile(Uint8Array.from(concatenateBytes(...parts)), "compressed-dwarf.bin"),
    candidates
  };
};
