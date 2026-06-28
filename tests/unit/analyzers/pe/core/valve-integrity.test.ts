"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePeHeaders } from "../../../../../analyzers/pe/core/index.js";
import { parseValveIntegrityBlock } from "../../../../../analyzers/pe/core/valve-integrity.js";
import { MockFile } from "../../../../helpers/mock-file.js";

// Steam-like sample layout from https://face.0xff.re/posts/patching-steam-binaries/.
const VALVE_BLOCK_PE_OFFSET = 0x158;
// Microsoft PE format: IMAGE_DOS_HEADER.e_lfanew is at 0x3c, so fixed fields end at 0x40.
const FIXED_DOS_HEADER_SIZE = 0x40;
const VALVE_BLOCK_HEADER_SIZE = 0x10;
const VALVE_SIGNATURE_SIZE = 0x80;
const FIXTURE_SIGNED_DATA_SIZE = 0x12345678;
const FIXTURE_TIMESTAMP = 0x64d1f2a0;
const FIXTURE_SIGNATURE_BYTE = 0xab;
const FIXTURE_SIGNATURE_HEX = FIXTURE_SIGNATURE_BYTE.toString(16).padStart(2, "0").repeat(VALVE_SIGNATURE_SIZE);

const createValveBlock = (): Uint8Array => {
  const bytes = new Uint8Array(VALVE_BLOCK_PE_OFFSET - FIXED_DOS_HEADER_SIZE);
  const view = new DataView(bytes.buffer);
  bytes.set([0x56, 0x4c, 0x56, 0x00]);
  view.setUint32(0x04, 1, true);
  view.setUint32(0x08, FIXTURE_SIGNED_DATA_SIZE, true);
  view.setUint32(0x0c, FIXTURE_TIMESTAMP, true);
  bytes.fill(FIXTURE_SIGNATURE_BYTE, VALVE_BLOCK_HEADER_SIZE, VALVE_BLOCK_HEADER_SIZE + VALVE_SIGNATURE_SIZE);
  return bytes;
};

const createPeWithValveIntegrityBlock = (): Uint8Array => {
  const optionalHeaderSize = 224;
  const bytes = new Uint8Array(VALVE_BLOCK_PE_OFFSET + 24 + optionalHeaderSize);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x5a4d, true); // PE files start with the little-endian MZ DOS signature.
  view.setUint16(0x08, 4, true);
  view.setUint32(0x3c, VALVE_BLOCK_PE_OFFSET, true);
  bytes.set(createValveBlock(), FIXED_DOS_HEADER_SIZE);
  bytes.set([0x50, 0x45, 0x00, 0x00], VALVE_BLOCK_PE_OFFSET);
  view.setUint16(VALVE_BLOCK_PE_OFFSET + 4, 0x014c, true); // Microsoft PE: IMAGE_FILE_MACHINE_I386.
  view.setUint16(VALVE_BLOCK_PE_OFFSET + 20, optionalHeaderSize, true);
  view.setUint16(VALVE_BLOCK_PE_OFFSET + 24, 0x10b, true);
  return bytes;
};

void test("parseValveIntegrityBlock decodes Valve PE integrity fields", () => {
  const result = parseValveIntegrityBlock(createValveBlock());

  assert.ok(result);
  assert.equal(result.version, 1);
  assert.equal(result.signedDataSize, FIXTURE_SIGNED_DATA_SIZE);
  assert.equal(result.timestamp, FIXTURE_TIMESTAMP);
  assert.equal(result.signatureHex, FIXTURE_SIGNATURE_HEX);
  // 0x158 PE header offset minus 0x40 fixed DOS header and 0x90 Valve block.
  assert.equal(result.paddingSize, 0x88);
  assert.equal(result.paddingZeroFilled, true);
  assert.equal(result.warnings, undefined);
});

void test("parseValveIntegrityBlock reports truncated blocks without throwing", () => {
  const bytes = new Uint8Array([0x56, 0x4c, 0x56, 0x00, 0x01]);

  const result = parseValveIntegrityBlock(bytes);

  assert.ok(result);
  assert.equal(result.version, undefined);
  assert.equal(result.signatureHex, undefined);
  assert.ok(result.warnings?.some(warning => /truncated/i.test(warning)));
});

void test("parseValveIntegrityBlock ignores ordinary DOS stubs", () => {
  const result = parseValveIntegrityBlock(new Uint8Array([0x0e, 0x1f, 0xba, 0x0e]));

  assert.equal(result, null);
});

void test("parsePeHeaders reports Valve integrity blocks instead of DOS disassembly", async () => {
  const parsed = await parsePeHeaders(new MockFile(createPeWithValveIntegrityBlock(), "steam-like.exe"));

  assert.ok(parsed);
  assert.equal(parsed.dos.stub.kind, "valve-integrity");
  assert.equal(parsed.dos.stub.valveIntegrity?.version, 1);
  assert.equal(parsed.dos.stub.valveIntegrity?.signedDataSize, FIXTURE_SIGNED_DATA_SIZE);
  assert.equal(parsed.dos.stub.valveIntegrity?.signatureHex, FIXTURE_SIGNATURE_HEX);
  assert.equal(parsed.dos.stub.valveIntegrity?.paddingZeroFilled, true);
});
