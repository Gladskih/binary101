import { dwarfUnitRoot } from "../../../../analyzers/dwarf/attribute-values.js";
"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  prepareDwarfSectionSources,
  type DwarfSectionCandidate
} from "../../../../analyzers/dwarf/compressed-sections.js";
import { analyzeDwarfSources } from "../../../../analyzers/dwarf/index.js";
import {
  TEST_DWARF_COMPRESSION,
  createCompressedDwarfSectionsFixture,
  encodeGnuCompressedSection,
  encodeElfCompressedSection
} from "../../../fixtures/dwarf-compressed-section-fixture.js";
import { TEST_DWARF } from "../../../fixtures/dwarf-fixture-encoding.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { splitInformation } from "../../../fixtures/dwarf-split-fixture.js";

const candidate = (
  bytes: number[],
  name = ".zdebug_info"
): { file: MockFile; value: DwarfSectionCandidate } => ({
  file: new MockFile(Uint8Array.from(bytes)),
  value: {
    section: { name, offset: 0, size: bytes.length, compressed: true },
    compression: { kind: "gnu-zlib" }
  }
});

void test("GNU-compressed split information keeps its DWO namespace and is decoded locally", async () => {
  const contents = candidate(encodeGnuCompressedSection(Uint8Array.from(splitInformation())), ".zdebug_info.dwo");
  const prepared = await prepareDwarfSectionSources(contents.file, [contents.value]);
  assert.equal(prepared.sources[0]?.decoded, true);
  assert.equal(prepared.sources[0]?.section.name, ".debug_info.dwo");
  assert.deepEqual(Array.from(await prepared.sources[0]!.reader.readBytes(0, splitInformation().length)),
    splitInformation());
  assert.deepEqual(prepared.issues, []);
});

const prepareWithoutDecompressionStream = async (
  file: MockFile,
  value: DwarfSectionCandidate
) => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "DecompressionStream");
  Object.defineProperty(globalThis, "DecompressionStream", {
    configurable: true,
    value: undefined
  });
  try {
    return await prepareDwarfSectionSources(file, [value]);
  } finally {
    if (descriptor) Object.defineProperty(globalThis, "DecompressionStream", descriptor);
    else Reflect.deleteProperty(globalThis, "DecompressionStream");
  }
};

void test("prepareDwarfSectionSources decodes GNU zlib sections for common analysis", async () => {
  const fixture = createCompressedDwarfSectionsFixture("gnu-zlib");

  const prepared = await prepareDwarfSectionSources(fixture.file, fixture.candidates);
  const dwarf = await analyzeDwarfSources(prepared.sources, "little");

  assert.deepEqual(prepared.issues, []);
  assert.equal(dwarfUnitRoot(dwarf.units[0])?.name, "main.c");
  assert.equal(dwarfUnitRoot(dwarf.units[0])?.producer, "fixture compiler");
  assert.equal(dwarf.sections[0]?.compressed, true);
  assert.equal(dwarf.sections[0]?.status, "decoded");
  assert.equal(prepared.sources[0]?.section.compressed, false);
});

void test("prepareDwarfSectionSources decodes big-endian ELF32 zlib sections", async () => {
  const fixture = createCompressedDwarfSectionsFixture("elf32-big-zlib");

  const prepared = await prepareDwarfSectionSources(fixture.file, fixture.candidates);
  const source = prepared.sources[0]!;
  const bytes = await source.reader.readBytes(
    TEST_DWARF.sectionOffset.start,
    source.section.size
  );
  const tail = await source.reader.readBytes(
    source.section.size - Uint8Array.BYTES_PER_ELEMENT,
    Uint16Array.BYTES_PER_ELEMENT
  );

  assert.deepEqual(prepared.issues, []);
  assert.ok(bytes.length > 0);
  assert.equal(source.decoded, true);
  assert.equal(tail.length, Uint8Array.BYTES_PER_ELEMENT);
});

void test("prepareDwarfSectionSources rejects zlib output size mismatches", async () => {
  const contents = new TextEncoder().encode("DWARF");
  const short = candidate(encodeGnuCompressedSection(
    contents,
    BigInt(contents.length + Uint8Array.BYTES_PER_ELEMENT)
  ));
  const long = candidate(encodeGnuCompressedSection(
    contents,
    BigInt(contents.length - Uint8Array.BYTES_PER_ELEMENT)
  ));

  const shortResult = await prepareDwarfSectionSources(short.file, [short.value]);
  const longResult = await prepareDwarfSectionSources(long.file, [long.value]);

  assert.ok(shortResult.issues[0]?.includes("does not match declared size"));
  assert.ok(longResult.issues[0]?.includes("exceeds declared size"));
  assert.equal(shortResult.sources[0]?.decoded, false);
  assert.equal(longResult.sources[0]?.decoded, false);
});

void test("prepareDwarfSectionSources reports corrupt and truncated payloads", async () => {
  const contents = new TextEncoder().encode("DWARF");
  const encoded = encodeGnuCompressedSection(contents);
  const corrupt = candidate(encoded.slice(0, encoded.length - Uint8Array.BYTES_PER_ELEMENT));
  const truncated = candidate(encoded);
  truncated.value.section.size += Uint8Array.BYTES_PER_ELEMENT;
  const emptyPayload = candidate(
    encodeGnuCompressedSection(new Uint8Array()).slice(
      0,
      TEST_DWARF_COMPRESSION.gnu.headerBytes
    )
  );

  const corruptResult = await prepareDwarfSectionSources(corrupt.file, [corrupt.value]);
  const truncatedResult = await prepareDwarfSectionSources(truncated.file, [truncated.value]);
  const emptyPayloadResult = await prepareDwarfSectionSources(
    emptyPayload.file,
    [emptyPayload.value]
  );

  assert.ok(corruptResult.issues[0]?.includes("decompression failed"));
  assert.equal(
    truncatedResult.issues[0],
    `.zdebug_info: compressed payload is truncated ` +
    `(${encoded.length - TEST_DWARF_COMPRESSION.gnu.headerBytes} of ` +
    `${encoded.length - TEST_DWARF_COMPRESSION.gnu.headerBytes + Uint8Array.BYTES_PER_ELEMENT} ` +
    `bytes readable).`
  );
  assert.ok(emptyPayloadResult.issues[0]?.includes("zlib decompression failed"));
});

void test("prepareDwarfSectionSources handles unavailable browser decompression", async () => {
  const contents = new TextEncoder().encode("DWARF");
  const compressed = candidate(encodeGnuCompressedSection(contents));

  const prepared = await prepareWithoutDecompressionStream(compressed.file, compressed.value);

  assert.ok(prepared.issues[0]?.includes("does not provide DecompressionStream"));
  assert.equal(prepared.sources[0]?.decoded, false);
});

void test("prepareDwarfSectionSources skips unsupported inventory and relocatable data", async () => {
  const invalid = candidate([], ".zdebug_vendor_unknown");
  const relocated = candidate([], ".zdebug_info");
  relocated.value.section.requiresRelocations = true;

  const inventory = await prepareDwarfSectionSources(invalid.file, [invalid.value]);
  const relocation = await prepareDwarfSectionSources(relocated.file, [relocated.value]);

  assert.deepEqual(inventory.issues, []);
  assert.deepEqual(relocation.issues, []);
  assert.equal(inventory.sources[0]?.decoded, false);
  assert.equal(relocation.sources[0]?.decoded, false);
});

void test("prepareDwarfSectionSources keeps ordinary sections on the original reader", async () => {
  const file = new MockFile(new TextEncoder().encode("DWARF"));
  const section = {
    name: ".debug_info",
    offset: 0,
    size: file.size,
    compressed: false
  };

  const prepared = await prepareDwarfSectionSources(file, [{ section, compression: null }]);

  assert.equal(prepared.sources[0]?.reader, file);
  assert.equal(prepared.sources[0]?.decoded, true);
});

for (const format of ["elf32-big-zstd", "elf32-little-zstd",
  "elf64-big-zstd", "elf64-little-zstd"] as const) {
  void test(`prepareDwarfSectionSources decodes ${format} locally`, async () => {
    const fixture = createCompressedDwarfSectionsFixture(format);
    const prepared = await prepareDwarfSectionSources(fixture.file, fixture.candidates);
    const dwarf = await analyzeDwarfSources(prepared.sources, "little");
    assert.deepEqual(prepared.issues, []);
    assert.equal(dwarfUnitRoot(dwarf.units[0])?.name, "main.c");
    assert.equal(dwarfUnitRoot(dwarf.units[0])?.producer, "fixture compiler");
    assert.equal(dwarf.sections[0]?.status, "decoded");
  });
}

const zstdCandidate = (contents: Uint8Array, declaredSize = contents.length) => {
  const encoded = candidate(encodeElfCompressedSection(contents, "elf64", "little",
    BigInt(declaredSize), TEST_DWARF_COMPRESSION.elf.zstdType), ".debug_info");
  encoded.value.compression = { kind: "elf", elfClass: "elf64", byteOrder: "little" };
  return encoded;
};

void test("Zstandard accepts a valid empty frame and rejects mismatched sizes", async () => {
  const contents = new TextEncoder().encode("DWARF");
  const empty = zstdCandidate(new Uint8Array());
  const short = zstdCandidate(contents, contents.length + 1);
  const long = zstdCandidate(contents, contents.length - 1);
  const emptyResult = await prepareDwarfSectionSources(empty.file, [empty.value]);
  const shortResult = await prepareDwarfSectionSources(short.file, [short.value]);
  const longResult = await prepareDwarfSectionSources(long.file, [long.value]);
  assert.deepEqual(emptyResult.issues, []);
  assert.equal(emptyResult.sources[0]?.section.size, 0);
  assert.equal(emptyResult.sources[0]?.decoded, true);
  assert.equal(shortResult.sources[0]?.decoded, false);
  assert.match(shortResult.issues[0]!, /does not match declared size/);
  assert.equal(longResult.sources[0]?.decoded, false);
  assert.match(longResult.issues[0]!, /Zstandard decompression failed/);
});

void test("Zstandard reports corruption even when the ELF header declares zero output", async () => {
  const corrupt = zstdCandidate(new Uint8Array());
  corrupt.file.data[TEST_DWARF_COMPRESSION.elf.elf64HeaderBytes] = 0;
  const truncated = zstdCandidate(new TextEncoder().encode("DWARF"));
  truncated.value.section.size -= 1;
  const corruptResult = await prepareDwarfSectionSources(new MockFile(corrupt.file.data), [corrupt.value]);
  const truncatedResult = await prepareDwarfSectionSources(truncated.file, [truncated.value]);
  assert.equal(corruptResult.sources[0]?.decoded, false);
  assert.match(corruptResult.issues[0]!, /Zstandard decompression failed/);
  assert.equal(truncatedResult.sources[0]?.decoded, false);
  assert.match(truncatedResult.issues[0]!, /Zstandard decompression failed/);
});

void test("Zstandard reports an ELF compression header with no payload", async () => {
  const empty = zstdCandidate(new Uint8Array());
  empty.value.section.size = TEST_DWARF_COMPRESSION.elf.elf64HeaderBytes;
  const result = await prepareDwarfSectionSources(empty.file, [empty.value]);
  assert.equal(result.sources[0]?.decoded, false);
  assert.match(result.issues[0]!, /Zstandard payload is empty/);
});
