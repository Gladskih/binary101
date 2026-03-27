"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDebugDirectory } from "../../analyzers/pe/debug-directory.js";
import { MockFile } from "../helpers/mock-file.js";

const encoder = new TextEncoder();
// Microsoft PE/COFF Debug Directory entries are 28 bytes wide.
const IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE = 28;
// PE/COFF debug type 2 is the CodeView record family.
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
// Microsoft CodeView RSDS records start with the ASCII signature "RSDS" in little-endian form.
const RSDS_SIGNATURE = 0x53445352;
// RSDS records use a fixed 24-byte header: signature, GUID, and age.
const RSDS_HEADER_SIZE = 24;
// Deterministic GUID bytes keep the endianness check explicit in the expected string form.
const RSDS_TEST_GUID_BYTES = Uint8Array.from([
  0x01, 0x02, 0x03, 0x04,
  0x05, 0x06,
  0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
]);
const rsdsRecordSize = (path: string): number => RSDS_HEADER_SIZE + encoder.encode(`${path}\0`).length;
const createDebugLayout = (
  start = IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE
): { reserve: (size: number) => number; size: () => number } => {
  let next = start;
  return {
    reserve: (size: number): number => {
      const offset = next;
      next += size;
      return offset;
    },
    size: (): number => next
  };
};
void test("parseDebugDirectory warns when a CodeView entry is smaller than the minimum RSDS header", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  const debugRva = 0x40;
  const dataRva = 0x80;
  dv.setUint32(debugRva + 12, IMAGE_DEBUG_TYPE_CODEVIEW, true);
  // RSDS needs 24 bytes: signature + GUID + age.
  dv.setUint32(debugRva + 16, RSDS_HEADER_SIZE - 1, true);
  dv.setUint32(debugRva + 20, dataRva, true);
  dv.setUint32(debugRva + 24, dataRva, true);

  const result = await parseDebugDirectory(
    new MockFile(bytes, "debug-short-rsds.bin"),
    [{ name: "DEBUG", rva: debugRva, size: IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE }],
    value => value
  );

  assert.equal(result.entry, null);
  assert.ok(
    result.warning && /codeview|rsds|small|truncated/i.test(result.warning),
    "Expected a warning for CodeView entries smaller than the RSDS minimum"
  );
});

void test("parseDebugDirectory warns when the RSDS path is not NUL-terminated within SizeOfData", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  const debugRva = 0x20;
  const dataRva = 0x80;
  const pathBytes = encoder.encode("abc");

  dv.setUint32(debugRva + 12, IMAGE_DEBUG_TYPE_CODEVIEW, true);
  // PE/COFF CodeView RSDS records store a NUL-terminated PDB path after the fixed 24-byte header.
  dv.setUint32(debugRva + 16, RSDS_HEADER_SIZE + pathBytes.length, true);
  dv.setUint32(debugRva + 20, dataRva, true);
  dv.setUint32(debugRva + 24, dataRva, true);
  dv.setUint32(dataRva + 0, RSDS_SIGNATURE, true);
  bytes.set(RSDS_TEST_GUID_BYTES, dataRva + 4);
  dv.setUint32(dataRva + 20, 1, true);
  bytes.set(pathBytes, dataRva + RSDS_HEADER_SIZE);

  const result = await parseDebugDirectory(
    new MockFile(bytes, "debug-rsds-missing-nul.bin"),
    [{ name: "DEBUG", rva: debugRva, size: IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE }],
    value => value
  );

  assert.equal(result.entry?.path, "abc");
  assert.ok(result.warning && /path|string|terminat|truncated/i.test(result.warning));
});

void test("parseDebugDirectory warns when the RSDS path stops mapping before its null terminator", async () => {
  const path = "AB";
  const rvaLayout = createDebugLayout();
  const fileLayout = createDebugLayout(0);
  const debugRva = rvaLayout.reserve(IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE);
  const dataRva = rvaLayout.reserve(rsdsRecordSize(path));
  const debugOffset = fileLayout.reserve(IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE);
  const dataOffset = fileLayout.reserve(rsdsRecordSize(path));
  const bytes = new Uint8Array(fileLayout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(debugOffset + 12, IMAGE_DEBUG_TYPE_CODEVIEW, true);
  dv.setUint32(debugOffset + 16, rsdsRecordSize(path), true);
  dv.setUint32(debugOffset + 20, dataRva, true);
  dv.setUint32(debugOffset + 24, 0, true);
  dv.setUint32(dataOffset + 0, RSDS_SIGNATURE, true);
  bytes.set(RSDS_TEST_GUID_BYTES, dataOffset + 4);
  dv.setUint32(dataOffset + 20, 1, true);
  encoder.encodeInto(`${path}\0`, new Uint8Array(bytes.buffer, dataOffset + RSDS_HEADER_SIZE));

  const sparseRvaToOff = (rva: number): number | null => {
    if (rva >= debugRva && rva < debugRva + IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE) {
      return debugOffset + (rva - debugRva);
    }
    if (rva >= dataRva && rva < dataRva + RSDS_HEADER_SIZE + 2) {
      return dataOffset + (rva - dataRva);
    }
    return null;
  };

  const result = await parseDebugDirectory(
    new MockFile(bytes, "debug-rsds-gap.bin"),
    [{ name: "DEBUG", rva: debugRva, size: IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE }],
    sparseRvaToOff
  );

  assert.equal(result.entry?.path, path);
  assert.ok(result.warning && /path|string|terminat|truncated/i.test(result.warning));
});

void test("parseDebugDirectory keeps later RSDS warnings instead of dropping them after an earlier directory warning", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  const debugRva = 0x20;
  const dataRva = 0x80;
  const pathBytes = encoder.encode("abc");

  dv.setUint32(debugRva + 12, IMAGE_DEBUG_TYPE_CODEVIEW, true);
  dv.setUint32(debugRva + 16, RSDS_HEADER_SIZE + pathBytes.length, true);
  dv.setUint32(debugRva + 20, dataRva, true);
  dv.setUint32(debugRva + 24, dataRva, true);
  dv.setUint32(dataRva + 0, RSDS_SIGNATURE, true);
  bytes.set(RSDS_TEST_GUID_BYTES, dataRva + 4);
  dv.setUint32(dataRva + 20, 1, true);
  bytes.set(pathBytes, dataRva + RSDS_HEADER_SIZE);

  const result = await parseDebugDirectory(
    new MockFile(bytes, "debug-multi-warning.bin"),
    [{ name: "DEBUG", rva: debugRva, size: IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE + 1 }],
    value => value
  );

  assert.equal(result.entry?.path, "abc");
  assert.ok(result.warning && /trailing/i.test(result.warning));
  assert.ok(result.warning && /terminat/i.test(result.warning));
});
