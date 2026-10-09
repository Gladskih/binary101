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
  assert.equal(await readPayload(
    encodeGnuCompressedSection(contents).slice(0, TEST_DWARF_COMPRESSION.gnu.headerBytes - 1),
    ".zdebug_info", { kind: "gnu-zlib" }, truncatedIssues), null);
  assert.equal(await readPayload(encodeGnuCompressedSection(contents, BigInt(contents.length),
    TEST_DWARF_COMPRESSION.gnu.magic + TEST_DWARF.flag.present),
  ".zdebug_info", { kind: "gnu-zlib" }, signatureIssues), null);
  assert.equal(await readPayload(encodeGnuCompressedSection(contents, BigInt(Number.MAX_SAFE_INTEGER) + 1n),
    ".zdebug_info", { kind: "gnu-zlib" }, unsafeSizeIssues), null);
  assert.ok(truncatedIssues[0]?.includes("header is truncated"));
  assert.ok(signatureIssues[0]?.includes("invalid GNU"));
  assert.equal(unsafeSizeIssues[0],
    `.zdebug_info uncompressed size ${BigInt(Number.MAX_SAFE_INTEGER) + 1n} is not a safe byte length.`);
});

for (const range of [{ offset: Number.NaN, size: 12 }, { offset: -1, size: 12 },
  { offset: 0, size: -1 }]) {
  void test(`GNU compression rejects invalid range ${JSON.stringify(range)}`, async () => {
    const file = new MockFile(Uint8Array.from(encodeGnuCompressedSection(new Uint8Array())));
    const issues: string[] = [];
    assert.equal(await readDwarfCompressionPayload(file,
      { name: ".zdebug_info", ...range, compressed: true }, { kind: "gnu-zlib" }, issues), null);
    assert.match(issues[0]!, /not a safe non-negative/);
  });
}

for (const size of [0, TEST_DWARF_COMPRESSION.gnu.headerBytes - 1]) {
  void test(`GNU compression never reads outside a ${size}-byte section`, async () => {
    const file = new MockFile(Uint8Array.from(encodeGnuCompressedSection(new Uint8Array())));
    const issues: string[] = [];
    assert.equal(await readDwarfCompressionPayload(file,
      { name: ".zdebug_info", offset: 0, size, compressed: true }, { kind: "gnu-zlib" }, issues), null);
    assert.equal(issues[0], `.zdebug_info GNU compression header is truncated (${size} of 12 bytes readable).`);
  });
}

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
  assert.equal((await readPayload(encodeElfCompressedSection(contents, "elf64", "little",
    BigInt(contents.length), TEST_DWARF_COMPRESSION.elf.zstdType
  ), ".debug_info", compression, zstdIssues))?.uncompressedSize, contents.length);
  assert.equal(await readPayload(encodeElfCompressedSection(contents, "elf64", "little",
    BigInt(contents.length), TEST_DWARF_COMPRESSION.elf.zstdType + TEST_DWARF.flag.present
  ), ".debug_info", compression, unknownIssues), null);
  assert.equal(await readPayload(encodeElfCompressedSection(
    contents,
    "elf64",
    "little",
    BigInt(contents.length),
    TEST_DWARF_COMPRESSION.elf.zlibType,
    TEST_DWARF.flag.present
  ), ".debug_info", compression, reservedIssues), null);
  assert.equal(await readPayload(encodeElfCompressedSection(contents, "elf64", "little",
    BigInt(Number.MAX_SAFE_INTEGER) + 1n
  ), ".debug_info", compression, unsafeSizeIssues), null);
  assert.ok(truncatedIssues[0]?.includes("header is truncated"));
  assert.deepEqual(zstdIssues, []);
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
