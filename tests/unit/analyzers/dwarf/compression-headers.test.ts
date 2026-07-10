"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  readDwarfCompressionPayload,
  type DwarfSectionCompression
} from "../../../../analyzers/dwarf/compression-headers.js";
import type { DwarfSectionInput } from "../../../../analyzers/dwarf/types.js";
import {
  TEST_DWARF_COMPRESSION,
  encodeElfCompressedSection,
  encodeGnuCompressedSection
} from "../../../fixtures/dwarf-compressed-section-fixture.js";
import { TEST_DWARF } from "../../../fixtures/dwarf-fixture-encoding.js";
import { MockFile } from "../../../helpers/mock-file.js";

const readPayload = async (
  bytes: number[],
  name: string,
  compression: DwarfSectionCompression,
  issues: string[] = []
) => {
  const file = new MockFile(Uint8Array.from(bytes));
  const section: DwarfSectionInput = {
    name,
    offset: 0,
    size: bytes.length,
    compressed: true
  };
  return readDwarfCompressionPayload(file, section, compression, issues);
};

void test("readDwarfCompressionPayload reads GNU and both ELF header layouts", async () => {
  const contents = new TextEncoder().encode("DWARF");
  const empty = await readPayload(
    encodeGnuCompressedSection(new Uint8Array()),
    ".zdebug_info",
    { kind: "gnu-zlib" }
  );

  const gnu = await readPayload(
    encodeGnuCompressedSection(contents),
    ".zdebug_info",
    { kind: "gnu-zlib" }
  );
  const elf32 = await readPayload(
    encodeElfCompressedSection(contents, "elf32", "big"),
    ".debug_info",
    { kind: "elf", elfClass: "elf32", byteOrder: "big" }
  );
  const elf64 = await readPayload(
    encodeElfCompressedSection(contents, "elf64", "little"),
    ".debug_info",
    { kind: "elf", elfClass: "elf64", byteOrder: "little" }
  );

  assert.equal(gnu?.name, ".debug_info");
  assert.equal(empty?.uncompressedSize, 0);
  assert.equal(gnu?.uncompressedSize, contents.length);
  assert.equal(elf32?.offset, TEST_DWARF_COMPRESSION.elf.elf32HeaderBytes);
  assert.equal(elf64?.offset, TEST_DWARF_COMPRESSION.elf.elf64HeaderBytes);
});

void test("readDwarfCompressionPayload rejects truncated and invalid GNU headers", async () => {
  const contents = new TextEncoder().encode("DWARF");
  const truncatedIssues: string[] = [];
  const signatureIssues: string[] = [];
  const unsafeSizeIssues: string[] = [];
  const invalidRangeIssues: string[] = [];
  const negativeOffsetIssues: string[] = [];
  const negativeSizeIssues: string[] = [];
  const zeroSizeIssues: string[] = [];
  const boundedIssues: string[] = [];
  const encoded = encodeGnuCompressedSection(contents);
  const encodedFile = new MockFile(Uint8Array.from(encoded));

  assert.equal(await readPayload(
    encoded.slice(0, TEST_DWARF_COMPRESSION.gnu.headerBytes - Uint8Array.BYTES_PER_ELEMENT),
    ".zdebug_info",
    { kind: "gnu-zlib" },
    truncatedIssues
  ), null);
  assert.equal(await readDwarfCompressionPayload(encodedFile, {
    name: ".zdebug_info",
    offset: Number.NaN,
    size: encoded.length,
    compressed: true
  }, { kind: "gnu-zlib" }, invalidRangeIssues), null);
  assert.equal(await readDwarfCompressionPayload(encodedFile, {
    name: ".zdebug_info",
    offset: -Uint8Array.BYTES_PER_ELEMENT,
    size: encoded.length,
    compressed: true
  }, { kind: "gnu-zlib" }, negativeOffsetIssues), null);
  assert.equal(await readDwarfCompressionPayload(encodedFile, {
    name: ".zdebug_info",
    offset: 0,
    size: -Uint8Array.BYTES_PER_ELEMENT,
    compressed: true
  }, { kind: "gnu-zlib" }, negativeSizeIssues), null);
  assert.equal(await readDwarfCompressionPayload(encodedFile, {
    name: ".zdebug_info",
    offset: 0,
    size: 0,
    compressed: true
  }, { kind: "gnu-zlib" }, zeroSizeIssues), null);
  assert.equal(await readDwarfCompressionPayload(encodedFile, {
    name: ".zdebug_info",
    offset: 0,
    size: TEST_DWARF_COMPRESSION.gnu.headerBytes - Uint8Array.BYTES_PER_ELEMENT,
    compressed: true
  }, { kind: "gnu-zlib" }, boundedIssues), null);
  assert.equal(await readPayload(
    encodeGnuCompressedSection(
      contents,
      BigInt(contents.length),
      TEST_DWARF_COMPRESSION.gnu.magic + TEST_DWARF.flag.present
    ),
    ".zdebug_info",
    { kind: "gnu-zlib" },
    signatureIssues
  ), null);
  assert.equal(await readPayload(
    encodeGnuCompressedSection(contents, BigInt(Number.MAX_SAFE_INTEGER) + 1n),
    ".zdebug_info",
    { kind: "gnu-zlib" },
    unsafeSizeIssues
  ), null);
  assert.ok(truncatedIssues[0]?.includes("header is truncated"));
  assert.ok(signatureIssues[0]?.includes("invalid GNU"));
  assert.equal(
    unsafeSizeIssues[0],
    `.zdebug_info uncompressed size ${BigInt(Number.MAX_SAFE_INTEGER) + 1n} ` +
    `is not a safe byte length.`
  );
  assert.ok(invalidRangeIssues[0]?.includes("not a safe non-negative"));
  assert.ok(negativeOffsetIssues[0]?.includes("not a safe non-negative"));
  assert.ok(negativeSizeIssues[0]?.includes("not a safe non-negative"));
  assert.ok(zeroSizeIssues[0]?.includes("header is truncated"));
  assert.ok(boundedIssues[0]?.includes(
    `${TEST_DWARF_COMPRESSION.gnu.headerBytes - Uint8Array.BYTES_PER_ELEMENT} of ` +
    `${TEST_DWARF_COMPRESSION.gnu.headerBytes} bytes readable`
  ));
});

void test("readDwarfCompressionPayload rejects unsupported and malformed ELF headers", async () => {
  const contents = new TextEncoder().encode("DWARF");
  const truncatedIssues: string[] = [];
  const zstdIssues: string[] = [];
  const unknownIssues: string[] = [];
  const reservedIssues: string[] = [];
  const unsafeSizeIssues: string[] = [];
  const compression = { kind: "elf", elfClass: "elf64", byteOrder: "little" } as const;

  assert.equal(await readPayload(encodeElfCompressedSection(
    contents,
    "elf64",
    "little"
  ).slice(
    0,
    TEST_DWARF_COMPRESSION.elf.elf64HeaderBytes - Uint8Array.BYTES_PER_ELEMENT
  ), ".debug_info", compression, truncatedIssues), null);
  assert.equal(await readPayload(encodeElfCompressedSection(
    contents,
    "elf64",
    "little",
    BigInt(contents.length),
    TEST_DWARF_COMPRESSION.elf.zstdType
  ), ".debug_info", compression, zstdIssues), null);
  assert.equal(await readPayload(encodeElfCompressedSection(
    contents,
    "elf64",
    "little",
    BigInt(contents.length),
    TEST_DWARF_COMPRESSION.elf.zstdType + TEST_DWARF.flag.present
  ), ".debug_info", compression, unknownIssues), null);
  assert.equal(await readPayload(encodeElfCompressedSection(
    contents,
    "elf64",
    "little",
    BigInt(contents.length),
    TEST_DWARF_COMPRESSION.elf.zlibType,
    TEST_DWARF.flag.present
  ), ".debug_info", compression, reservedIssues), null);
  assert.equal(await readPayload(encodeElfCompressedSection(
    contents,
    "elf64",
    "little",
    BigInt(Number.MAX_SAFE_INTEGER) + 1n
  ), ".debug_info", compression, unsafeSizeIssues), null);
  assert.ok(truncatedIssues[0]?.includes("header is truncated"));
  assert.equal(zstdIssues[0], ".debug_info: unsupported ELF compression Zstandard.");
  assert.equal(
    unknownIssues[0],
    `.debug_info: unsupported ELF compression type ` +
    `${TEST_DWARF_COMPRESSION.elf.zstdType + TEST_DWARF.flag.present}.`
  );
  assert.ok(reservedIssues[0]?.includes("reserved field"));
  assert.equal(
    unsafeSizeIssues[0],
    `.debug_info uncompressed size ${BigInt(Number.MAX_SAFE_INTEGER) + 1n} ` +
    `is not a safe byte length.`
  );
});
