"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { isPeWindowsParseResult, parsePe } from "../../analyzers/pe/index.js";
import { createPePlusWithSection } from "../fixtures/sample-files-pe.js";
import { MockFile } from "../helpers/mock-file.js";

// These offsets mirror createPePlusWithSection in tests/fixtures/sample-files-pe.ts.
// They let this integration test add a second section while keeping parsePe on a
// real PE header path instead of calling the detector directly.
// PE header and section table field offsets are specified by Microsoft.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
const PE_HEADER_OFFSET = 0x40;
const COFF_HEADER_OFFSET = PE_HEADER_OFFSET + 4;
const OPTIONAL_HEADER_OFFSET = COFF_HEADER_OFFSET + 20;
const OPTIONAL_HEADER_SIZE = 240;
const SECTION_HEADER_OFFSET = OPTIONAL_HEADER_OFFSET + OPTIONAL_HEADER_SIZE;
const FILE_ALIGNMENT = 0x200;
const TEXT_SECTION_RAW_END = 0x400;
const PE_SECTION_HEADER_BYTES = 40;
const PE_SIZE_OF_IMAGE_OFFSET = 56;
const PE_SECTION_VIRTUAL_SIZE_OFFSET = 8;
const PE_SECTION_VIRTUAL_ADDRESS_OFFSET = 12;
const PE_SECTION_SIZE_OF_RAW_DATA_OFFSET = 16;
const PE_SECTION_POINTER_TO_RAW_DATA_OFFSET = 20;
const PE_SECTION_CHARACTERISTICS_OFFSET = 36;
const BUN_GRAPH_BYTES = 16;
const BUN_MODULE_LIST_BYTES = 8;
const BUN_COMPILE_ARGV_BYTES = 4;
const BUN_ENTRY_POINT_ID = 1;
const BUN_SECTION_VIRTUAL_ADDRESS = 0x2000;
const BUN_IMAGE_SIZE = 0x3000;
const PE_IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
const PE_IMAGE_SCN_MEM_READ = 0x40000000;
// Bun StandaloneModuleGraph.Offsets is byte_count, modules_ptr, entry_point_id,
// compile_exec_argv_ptr, flags, then the standalone trailer.
// https://github.com/oven-sh/bun/blob/main/src/standalone_graph/StandaloneModuleGraph.zig
const BUN_TRAILER = new TextEncoder().encode("\n---- Bun! ----\n");
const BUN_SECTION_NAME_BYTES = new TextEncoder().encode(".bun");
const BUN_OFFSETS64 = {
  byteCount: 0,
  modulesPointer: 8,
  entryPointId: 16,
  compileArgvPointer: 20,
  flags: 28
};
const BUN_OFFSETS64_BYTES = BUN_OFFSETS64.flags + Uint32Array.BYTES_PER_ELEMENT;

const writeBunOffsets64 = (view: DataView): void => {
  view.setBigUint64(BUN_OFFSETS64.byteCount, BigInt(BUN_GRAPH_BYTES), true);
  view.setUint32(BUN_OFFSETS64.modulesPointer, 0, true);
  view.setUint32(BUN_OFFSETS64.modulesPointer + Uint32Array.BYTES_PER_ELEMENT, BUN_MODULE_LIST_BYTES, true);
  view.setUint32(BUN_OFFSETS64.entryPointId, BUN_ENTRY_POINT_ID, true);
  view.setUint32(BUN_OFFSETS64.compileArgvPointer, BUN_MODULE_LIST_BYTES, true);
  view.setUint32(BUN_OFFSETS64.compileArgvPointer + Uint32Array.BYTES_PER_ELEMENT, BUN_COMPILE_ARGV_BYTES, true);
};

const createBunPayload = (): Uint8Array => {
  const graphBytes = new Uint8Array(BUN_GRAPH_BYTES);
  const offsets = new Uint8Array(BUN_OFFSETS64_BYTES);
  writeBunOffsets64(new DataView(offsets.buffer));
  const payload = new Uint8Array(graphBytes.byteLength + offsets.byteLength + BUN_TRAILER.byteLength);
  payload.set(graphBytes);
  payload.set(offsets, graphBytes.byteLength);
  payload.set(BUN_TRAILER, graphBytes.byteLength + offsets.byteLength);
  return payload;
};

const createPePlusWithBunSection = (): Uint8Array => {
  const base = createPePlusWithSection();
  const payload = createBunPayload();
  const bunRawSize = FILE_ALIGNMENT;
  const bytes = new Uint8Array(TEXT_SECTION_RAW_END + bunRawSize);
  bytes.set(base);
  const view = new DataView(bytes.buffer);
  view.setUint16(COFF_HEADER_OFFSET + 2, 2, true);
  view.setUint32(OPTIONAL_HEADER_OFFSET + PE_SIZE_OF_IMAGE_OFFSET, BUN_IMAGE_SIZE, true);
  const headerOffset = SECTION_HEADER_OFFSET + PE_SECTION_HEADER_BYTES;
  BUN_SECTION_NAME_BYTES.forEach((byte, index) => {
    view.setUint8(headerOffset + index, byte);
  });
  view.setUint32(
    headerOffset + PE_SECTION_VIRTUAL_SIZE_OFFSET,
    BigUint64Array.BYTES_PER_ELEMENT + payload.byteLength,
    true
  );
  view.setUint32(headerOffset + PE_SECTION_VIRTUAL_ADDRESS_OFFSET, BUN_SECTION_VIRTUAL_ADDRESS, true);
  view.setUint32(headerOffset + PE_SECTION_SIZE_OF_RAW_DATA_OFFSET, bunRawSize, true);
  view.setUint32(headerOffset + PE_SECTION_POINTER_TO_RAW_DATA_OFFSET, TEXT_SECTION_RAW_END, true);
  view.setUint32(
    headerOffset + PE_SECTION_CHARACTERISTICS_OFFSET,
    PE_IMAGE_SCN_CNT_INITIALIZED_DATA | PE_IMAGE_SCN_MEM_READ,
    true
  );
  view.setBigUint64(TEXT_SECTION_RAW_END, BigInt(payload.byteLength), true);
  bytes.set(payload, TEXT_SECTION_RAW_END + BigUint64Array.BYTES_PER_ELEMENT);
  return bytes;
};

void test("parsePe attaches high-confidence packaging signature analysis", async () => {
  const parsed = await parsePe(new MockFile(createPePlusWithBunSection(), "bun.exe"));

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.equal(parsed?.packers?.findings[0]?.id, "bun-standalone");
});
