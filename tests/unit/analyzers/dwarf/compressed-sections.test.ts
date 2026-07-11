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
  encodeGnuCompressedSection
} from "../../../fixtures/dwarf-compressed-section-fixture.js";
import {
  TEST_DWARF,
  concatenateBytes
} from "../../../fixtures/dwarf-fixture-encoding.js";
import { MockFile } from "../../../helpers/mock-file.js";

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
  assert.equal(dwarf.units[0]?.root?.name, "main.c");
  assert.equal(dwarf.units[0]?.root?.producer, "fixture compiler");
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

void test("prepareDwarfSectionSources enforces the total decompression budget", async () => {
  const contents = new TextEncoder().encode("DWARF");
  const oversized = candidate(encodeGnuCompressedSection(
    contents,
    BigInt(
      TEST_DWARF_COMPRESSION.maximumDecompressedBytes + Uint8Array.BYTES_PER_ELEMENT
    )
  ));

  const prepared = await prepareDwarfSectionSources(oversized.file, [oversized.value]);

  assert.equal(
    prepared.issues[0],
    `.zdebug_info: uncompressed size ` +
    `${TEST_DWARF_COMPRESSION.maximumDecompressedBytes + Uint8Array.BYTES_PER_ELEMENT} ` +
    `exceeds the remaining DWARF decompression budget ` +
    `${TEST_DWARF_COMPRESSION.maximumDecompressedBytes}.`
  );
  assert.equal(prepared.sources[0]?.decoded, false);
});

void test("prepareDwarfSectionSources consumes an exact custom budget across sections", async () => {
  const contents = new TextEncoder().encode("DWARF");
  const encoded = encodeGnuCompressedSection(contents);
  const file = new MockFile(Uint8Array.from(concatenateBytes(encoded, encoded)));
  const first = candidate(encoded).value;
  const second = candidate(encoded, ".zdebug_abbrev").value;
  second.section.offset = encoded.length;

  const exact = await prepareDwarfSectionSources(file, [first], contents.length);
  const exhausted = await prepareDwarfSectionSources(
    file,
    [first, second],
    contents.length
  );

  assert.deepEqual(exact.issues, []);
  assert.equal(exact.sources[0]?.decoded, true);
  assert.ok(exhausted.issues[0]?.includes("remaining DWARF decompression budget 0"));
  assert.equal(exhausted.sources[1]?.decoded, false);
});

void test("prepareDwarfSectionSources handles unavailable browser decompression", async () => {
  const contents = new TextEncoder().encode("DWARF");
  const compressed = candidate(encodeGnuCompressedSection(contents));

  const prepared = await prepareWithoutDecompressionStream(compressed.file, compressed.value);

  assert.ok(prepared.issues[0]?.includes("does not provide DecompressionStream"));
  assert.equal(prepared.sources[0]?.decoded, false);
});

void test("prepareDwarfSectionSources skips unsupported inventory and relocatable data", async () => {
  const invalid = candidate([], ".zdebug_ranges");
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
