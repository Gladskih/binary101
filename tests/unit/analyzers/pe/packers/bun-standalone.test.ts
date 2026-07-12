"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBunStandalone } from "../../../../../analyzers/pe/packers/bun-standalone.js";
import type { BunStandaloneDetectorInput } from "../../../../../analyzers/pe/packers/types.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import type { PeSection } from "../../../../../analyzers/pe/types.js";
import { expectDefined } from "../../../../helpers/expect-defined.js";
import { MockFile } from "../../../../helpers/mock-file.js";

// Non-zero raw placement exercises absolute range calculation instead of the
// accidental offset-zero path.
const SECTION_START = 0x40;
const SECTION_RAW_SIZE = 0x100;
const BUN_GRAPH_BYTES = 32;
const BUN_MODULE_LIST_BYTES = 16;
const BUN_COMPILE_ARGV_BYTES = 4;
const BUN_ENTRY_POINT_ID = 7;
const BUN_FLAGS_DISABLE_ENV_AND_BUNFIG = 3;
const BUN_SECTION_VIRTUAL_ADDRESS = 0x2000;
// PE section characteristic bits come from the Microsoft PE section table spec.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
const PE_IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
const PE_IMAGE_SCN_MEM_READ = 0x40000000;
// Bun StandaloneModuleGraph.Offsets is byte_count, modules_ptr, entry_point_id,
// compile_exec_argv_ptr, flags, then the standalone trailer.
// https://github.com/oven-sh/bun/blob/main/src/standalone_graph/StandaloneModuleGraph.zig
const BUN_TRAILER = new TextEncoder().encode("\n---- Bun! ----\n");
const BUN_OFFSETS64 = {
  byteCount: 0,
  modulesPointer: 8,
  entryPointId: 16,
  compileArgvPointer: 20,
  flags: 28
};
const BUN_OFFSETS32 = {
  byteCount: 0,
  modulesPointer: 4,
  entryPointId: 12,
  compileArgvPointer: 16,
  flags: 24
};
const BUN_OFFSETS64_BYTES = BUN_OFFSETS64.flags + Uint32Array.BYTES_PER_ELEMENT;
const BUN_OFFSETS32_BYTES = BUN_OFFSETS32.flags + Uint32Array.BYTES_PER_ELEMENT;

const writeBunOffsets64 = (view: DataView): void => {
  view.setBigUint64(BUN_OFFSETS64.byteCount, BigInt(BUN_GRAPH_BYTES), true);
  view.setUint32(BUN_OFFSETS64.modulesPointer, 0, true);
  view.setUint32(BUN_OFFSETS64.modulesPointer + Uint32Array.BYTES_PER_ELEMENT, BUN_MODULE_LIST_BYTES, true);
  view.setUint32(BUN_OFFSETS64.entryPointId, BUN_ENTRY_POINT_ID, true);
  view.setUint32(BUN_OFFSETS64.compileArgvPointer, BUN_MODULE_LIST_BYTES, true);
  view.setUint32(BUN_OFFSETS64.compileArgvPointer + Uint32Array.BYTES_PER_ELEMENT, BUN_COMPILE_ARGV_BYTES, true);
  view.setUint32(BUN_OFFSETS64.flags, BUN_FLAGS_DISABLE_ENV_AND_BUNFIG, true);
};

const writeBunOffsets32 = (view: DataView): void => {
  view.setUint32(BUN_OFFSETS32.byteCount, BUN_GRAPH_BYTES, true);
  view.setUint32(BUN_OFFSETS32.modulesPointer, 0, true);
  view.setUint32(BUN_OFFSETS32.modulesPointer + Uint32Array.BYTES_PER_ELEMENT, BUN_MODULE_LIST_BYTES, true);
  view.setUint32(BUN_OFFSETS32.entryPointId, BUN_ENTRY_POINT_ID, true);
  view.setUint32(BUN_OFFSETS32.compileArgvPointer, BUN_MODULE_LIST_BYTES, true);
  view.setUint32(BUN_OFFSETS32.compileArgvPointer + Uint32Array.BYTES_PER_ELEMENT, BUN_COMPILE_ARGV_BYTES, true);
  view.setUint32(BUN_OFFSETS32.flags, BUN_FLAGS_DISABLE_ENV_AND_BUNFIG, true);
};

const createBunPayload = (offsetsSize: number, writeOffsets: (view: DataView) => void): Uint8Array => {
  const graphBytes = new Uint8Array(BUN_GRAPH_BYTES);
  const offsets = new Uint8Array(offsetsSize);
  writeOffsets(new DataView(offsets.buffer));
  const payload = new Uint8Array(graphBytes.byteLength + offsets.byteLength + BUN_TRAILER.byteLength);
  payload.set(graphBytes);
  payload.set(offsets, graphBytes.byteLength);
  payload.set(BUN_TRAILER, graphBytes.byteLength + offsets.byteLength);
  return payload;
};

const createBunSection = (offsetsSize: number, writeOffsets: (view: DataView) => void): Uint8Array => {
  const payload = createBunPayload(offsetsSize, writeOffsets);
  const section = new Uint8Array(SECTION_RAW_SIZE);
  new DataView(section.buffer).setBigUint64(0, BigInt(payload.byteLength), true);
  section.set(payload, BigUint64Array.BYTES_PER_ELEMENT);
  return section;
};

const createBunSection64 = (): Uint8Array =>
  createBunSection(BUN_OFFSETS64_BYTES, writeBunOffsets64);

const createBunSection32 = (): Uint8Array =>
  createBunSection(BUN_OFFSETS32_BYTES, writeBunOffsets32);

const createDirectBunSection64 = (): { section: Uint8Array; virtualSize: number } => {
  const payload = createBunPayload(BUN_OFFSETS64_BYTES, writeBunOffsets64);
  const section = new Uint8Array(SECTION_RAW_SIZE);
  section.set(payload);
  return { section, virtualSize: payload.byteLength };
};

const createInput = (
  sectionBytes: Uint8Array,
  imagePointerBytes: BunStandaloneDetectorInput["imagePointerBytes"] = 8,
  sizeOfRawData = sectionBytes.byteLength,
  virtualSize = sectionBytes.byteLength
) => {
  const bytes = new Uint8Array(SECTION_START + sectionBytes.byteLength);
  bytes.set(sectionBytes, SECTION_START);
  const section: PeSection = {
    name: inlinePeSectionName(".bun"),
    virtualSize,
    virtualAddress: BUN_SECTION_VIRTUAL_ADDRESS,
    sizeOfRawData,
    pointerToRawData: SECTION_START,
    characteristics: PE_IMAGE_SCN_CNT_INITIALIZED_DATA | PE_IMAGE_SCN_MEM_READ
  };
  return {
    reader: new MockFile(bytes, "bun.exe"),
    sections: [section],
    imagePointerBytes
  } satisfies BunStandaloneDetectorInput;
};

void test("detectBunStandalone reports a valid Bun .bun section with parsed offset details", async () => {
  const result = await detectBunStandalone(createInput(createBunSection64()));

  assert.equal(result.warnings.length, 0);
  assert.equal(result.findings[0]?.id, "bun-standalone");
  assert.deepEqual(result.findings[0]?.offsetMetadata, {
    byteCount: BUN_GRAPH_BYTES,
    compileArgvBytes: BUN_COMPILE_ARGV_BYTES,
    entryPointId: BUN_ENTRY_POINT_ID,
    flags: BUN_FLAGS_DISABLE_ENV_AND_BUNFIG,
    moduleListBytes: BUN_MODULE_LIST_BYTES
  });
  assert.equal(result.findings[0]?.storage, "length-prefixed");
  assert.equal(result.findings[0]?.sectionStart, SECTION_START);
  assert.equal(result.findings[0]?.sectionSize, SECTION_RAW_SIZE);
  assert.equal(result.findings[0]?.payloadStart, SECTION_START + BigUint64Array.BYTES_PER_ELEMENT);
});

void test("detectBunStandalone reports direct .bun payloads using VirtualSize", async () => {
  const fixture = createDirectBunSection64();
  const result = await detectBunStandalone(
    createInput(fixture.section, 8, fixture.section.byteLength, fixture.virtualSize)
  );

  assert.equal(result.warnings.length, 0);
  assert.equal(result.findings[0]?.storage, "section-virtual-data");
  assert.equal(result.findings[0]?.payloadStart, SECTION_START);
  assert.equal(result.findings[0]?.payloadSize, fixture.virtualSize);
  assert.equal(result.findings[0]?.offsetMetadata?.byteCount, BUN_GRAPH_BYTES);
});

void test("detectBunStandalone parses 32-bit Bun offset layouts", async () => {
  const result = await detectBunStandalone(createInput(createBunSection32(), 4));

  assert.equal(result.warnings.length, 0);
  assert.equal(result.findings[0]?.offsetMetadata?.entryPointId, BUN_ENTRY_POINT_ID);
});

void test("detectBunStandalone keeps a verified payload when its offsets block is absent", async () => {
  const section = new Uint8Array(BUN_TRAILER.byteLength);
  section.set(BUN_TRAILER);

  const result = await detectBunStandalone(
    createInput(section, 8, section.byteLength, section.byteLength)
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0]?.offsetMetadata, undefined);
  assert.deepEqual(result.warnings, [
    "Bun .bun payload is too small to contain offsets before the trailer."
  ]);
});

void test("detectBunStandalone omits unsafe offset metadata without rejecting the payload", async () => {
  const section = createBunSection64();
  const offsetsStart = BigUint64Array.BYTES_PER_ELEMENT + BUN_GRAPH_BYTES;
  new DataView(section.buffer).setBigUint64(
    offsetsStart + BUN_OFFSETS64.byteCount,
    BigInt(Number.MAX_SAFE_INTEGER) + 1n,
    true
  );

  const result = await detectBunStandalone(createInput(section));

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0]?.offsetMetadata, undefined);
  assert.deepEqual(result.warnings, [
    "Bun .bun offsets byte_count exceeds Number.MAX_SAFE_INTEGER."
  ]);
});

void test("detectBunStandalone reports invalid pointers and reserved flag bits", async () => {
  const section = createBunSection64();
  const offsetsStart = BigUint64Array.BYTES_PER_ELEMENT + BUN_GRAPH_BYTES;
  const view = new DataView(section.buffer);
  // Bun pointers must fit byte_count; 8 is smaller than both fixture ranges.
  view.setBigUint64(offsetsStart + BUN_OFFSETS64.byteCount, 8n, true);
  // StandaloneModuleGraph.Flags reserves every bit above the documented low four.
  // https://github.com/oven-sh/bun/blob/main/src/standalone_graph/StandaloneModuleGraph.zig
  view.setUint32(offsetsStart + BUN_OFFSETS64.flags, 0x10, true);

  const result = await detectBunStandalone(createInput(section));

  assert.equal(result.findings[0]?.offsetMetadata?.flags, 0x10);
  assert.deepEqual(result.warnings, [
    "Bun .bun module-list pointer is outside byte_count.",
    "Bun .bun compile argv pointer is outside byte_count.",
    "Bun .bun flags contain non-zero reserved bits."
  ]);
});

void test("detectBunStandalone rejects truncated .bun length fields without throwing", async () => {
  const input = createInput(new Uint8Array(4));

  const result = await detectBunStandalone(input);

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.warnings, ["Bun .bun section is truncated before its 8-byte payload length."]);
});

void test("detectBunStandalone does not read length fields past declared raw section data", async () => {
  const physicallyAvailableLengthBytes = new Uint8Array(BigUint64Array.BYTES_PER_ELEMENT);

  const result = await detectBunStandalone(createInput(physicallyAvailableLengthBytes, 8, 4));

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.warnings, ["Bun .bun section is truncated before its 8-byte payload length."]);
});

void test("detectBunStandalone rejects oversized declared payloads", async () => {
  const section = new Uint8Array(SECTION_RAW_SIZE);
  new DataView(section.buffer).setBigUint64(0, BigInt(SECTION_RAW_SIZE), true);

  const result = await detectBunStandalone(createInput(section));

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.warnings, ["Bun .bun declared payload length extends past the section or EOF."]);
});

void test("detectBunStandalone rejects unsafe declared payload ranges", async () => {
  const section = new Uint8Array(SECTION_RAW_SIZE);
  new DataView(section.buffer).setBigUint64(0, BigInt(Number.MAX_SAFE_INTEGER), true);

  const result = await detectBunStandalone(createInput(section));

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.warnings, ["Bun .bun declared payload range exceeds Number.MAX_SAFE_INTEGER."]);
});

void test("detectBunStandalone rejects .bun payloads with a missing trailer", async () => {
  const section = createBunSection64();
  const payloadSize = Number(new DataView(section.buffer).getBigUint64(0, true));
  const trailerByteOffset = BigUint64Array.BYTES_PER_ELEMENT + payloadSize - 1;
  const originalTrailerByte = expectDefined(section[trailerByteOffset]);
  section[trailerByteOffset] = originalTrailerByte ^ 0xff;

  const result = await detectBunStandalone(createInput(section));

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.warnings, [
    "Bun .bun payload is missing the expected standalone module-graph trailer."
  ]);
});
