"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseBoundImports, parseDelayImports } from "../../analyzers/pe/bound-delay.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();

void test("parseDelayImports warns when a mapped DLL name offset falls past EOF", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const descriptorOffset = 0x20;
  dv.setUint32(descriptorOffset + 0, 0, true);
  dv.setUint32(descriptorOffset + 4, 0x40, true);

  const result = expectDefined(await parseDelayImports(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: 32 }],
    value => (value === descriptorOffset ? descriptorOffset : value === 0 ? null : value + 0x200),
    () => {},
    false,
    0x400000
  ));

  assert.ok(result.warning?.toLowerCase().includes("name rva"));
});

void test("parseDelayImports warns when a hint/name entry is shorter than two bytes", async () => {
  const bytes = new Uint8Array(0x81).fill(0);
  const dv = new DataView(bytes.buffer);
  const descriptorOffset = 0x20;
  const dllNameRva = 0x40;
  const thunkTableRva = 0x60;
  const truncatedHintNameRva = 0x80;
  dv.setUint32(descriptorOffset + 0, 0, true);
  dv.setUint32(descriptorOffset + 4, dllNameRva, true);
  encoder.encodeInto("delay.dll\0", new Uint8Array(bytes.buffer, dllNameRva));
  dv.setUint32(descriptorOffset + 16, thunkTableRva, true);
  // The final byte in the file is the first byte of a hint/name entry, so reading the required 2-byte hint
  // must report truncation rather than silently succeed.
  dv.setUint32(thunkTableRva, truncatedHintNameRva, true);

  const result = expectDefined(await parseDelayImports(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: 32 }],
    value => value,
    () => {},
    false,
    0x400000
  ));

  assert.ok(result.warning?.toLowerCase().includes("truncated"));
});

void test("parseDelayImports warns when file-form Attributes is non-zero", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const descriptorOffset = 0x20;
  const dllNameRva = 0x60;
  dv.setUint32(descriptorOffset + 0, 1, true); // File-form delay descriptors must store 0 here per PE/COFF.
  dv.setUint32(descriptorOffset + 4, dllNameRva, true);
  encoder.encodeInto("delay.dll\0", new Uint8Array(bytes.buffer, dllNameRva));

  const result = expectDefined(await parseDelayImports(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: 32 }],
    value => value,
    () => {},
    false,
    0x400000
  ));

  assert.ok(result.warning?.toLowerCase().includes("attribute"));
});

void test("parseBoundImports clamps module names to the declared directory span", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const directoryOffset = 0x20;
  const directorySize = 20;
  dv.setUint32(directoryOffset + 0, 0x11111111, true);
  // Offset 16 leaves only four bytes after the required all-zero terminator descriptor at +8.
  dv.setUint16(directoryOffset + 4, 16, true);
  dv.setUint16(directoryOffset + 6, 0, true);
  encoder.encodeInto("ABCDEF\0", new Uint8Array(bytes.buffer, directoryOffset + 16));

  const result = await parseBoundImports(
    new MockFile(bytes),
    [{ name: "BOUND_IMPORT", rva: directoryOffset, size: directorySize }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  assert.equal(definedResult.entries[0]?.name, "ABCD");
  assert.ok(definedResult.warning?.toLowerCase().includes("name"));
});
