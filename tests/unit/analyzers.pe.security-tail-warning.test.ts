import assert from "node:assert/strict";
import { test } from "node:test";

import { parsePe } from "../../analyzers/pe/index.js";
import { createPeWithSectionAndIat } from "../fixtures/sample-files-pe.js";
import { MockFile } from "../helpers/mock-file.js";

const IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
const IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
const RSDS_SIGNATURE = 0x53445352;

const getPeView = (bytes: Uint8Array): DataView =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

const getDataDirectoryEntryOffset = (bytes: Uint8Array, index: number): number => {
  const view = getPeView(bytes);
  return view.getUint32(0x3c, true) + 4 + 20 + 0x60 + index * 8;
};

void test("parsePe omits the generic SECURITY tail warning when parsed debug raw data explains the file tail", async () => {
  const baseBytes = createPeWithSectionAndIat();
  const certOff = baseBytes.length - 0x20;
  // RSDS record uses a 24-byte fixed header plus a NUL-terminated path.
  const debugPayloadSize = 26;
  const bytes = new Uint8Array(certOff + 8 + debugPayloadSize);
  bytes.set(baseBytes);
  const view = getPeView(bytes);
  const securityEntryOffset = getDataDirectoryEntryOffset(bytes, IMAGE_DIRECTORY_ENTRY_SECURITY);
  const debugEntryOffset = getDataDirectoryEntryOffset(bytes, IMAGE_DIRECTORY_ENTRY_DEBUG);

  // Microsoft PE format: Certificate Table is data-directory entry 4 and stores a file pointer.
  view.setUint32(securityEntryOffset, certOff, true);
  view.setUint32(securityEntryOffset + 4, 8, true);
  view.setUint32(certOff, 8, true);
  view.setUint16(certOff + 4, 0x0200, true);
  view.setUint16(certOff + 6, 0x0001, true);

  // Microsoft PE format: DEBUG raw data is addressed by PointerToRawData in IMAGE_DEBUG_DIRECTORY.
  view.setUint32(debugEntryOffset, 0x1000, true);
  view.setUint32(debugEntryOffset + 4, 28, true);
  view.setUint32(0x200 + 12, 2, true);
  view.setUint32(0x200 + 16, debugPayloadSize, true);
  view.setUint32(0x200 + 20, 0, true);
  view.setUint32(0x200 + 24, certOff + 8, true);
  view.setUint32(certOff + 8, RSDS_SIGNATURE, true);
  view.setUint32(certOff + 28, 1, true);
  bytes[certOff + 32] = 0x61; // "a"
  bytes[certOff + 33] = 0x00;

  const result = await parsePe(new MockFile(bytes, "cert-followed-by-debug.exe"));

  assert.ok(result);
  assert.ok(result.debug?.entry);
  assert.ok(!result.security?.warnings?.some(warning => /bytes after the declared table/i.test(warning)));
});

void test("parsePe keeps the generic SECURITY tail warning when no proven file span explains the tail", async () => {
  const baseBytes = createPeWithSectionAndIat();
  const certOff = baseBytes.length - 16;
  const bytes = new Uint8Array(baseBytes.length);
  bytes.set(baseBytes);
  const view = getPeView(bytes);
  const securityEntryOffset = getDataDirectoryEntryOffset(bytes, IMAGE_DIRECTORY_ENTRY_SECURITY);

  // Microsoft PE format: the Certificate Table directory entry stores a file pointer and byte size.
  view.setUint32(securityEntryOffset, certOff, true);
  view.setUint32(securityEntryOffset + 4, 8, true);
  view.setUint32(certOff, 8, true);
  view.setUint16(certOff + 4, 0x0200, true);
  view.setUint16(certOff + 6, 0x0001, true);

  const result = await parsePe(new MockFile(bytes, "cert-with-unexplained-tail.exe"));

  assert.ok(result);
  assert.ok(result.security?.warnings?.some(warning => /bytes after the declared table/i.test(warning)));
});
