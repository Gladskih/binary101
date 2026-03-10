"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDebugDirectory } from "../../analyzers/pe/debug-directory.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";

const encoder = new TextEncoder();

void test("parseDebugDirectory reads CodeView RSDS entry", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  const debugRva = 0x40;
  const dataRva = 0x120;
  dv.setUint32(debugRva + 12, 2, true);
  dv.setUint32(debugRva + 16, 32, true);
  dv.setUint32(debugRva + 20, dataRva, true);
  dv.setUint32(debugRva + 24, dataRva, true);
  dv.setUint32(dataRva + 0, 0x53445352, true);
  dv.setUint32(dataRva + 4, 0x11223344, true);
  dv.setUint16(dataRva + 8, 0x5566, true);
  dv.setUint16(dataRva + 10, 0x7788, true);
  dv.setUint8(dataRva + 12, 0xaa);
  dv.setUint8(dataRva + 13, 0xbb);
  dv.setUint8(dataRva + 14, 0xcc);
  dv.setUint8(dataRva + 15, 0xdd);
  dv.setUint8(dataRva + 16, 0xee);
  dv.setUint8(dataRva + 17, 0xff);
  dv.setUint8(dataRva + 18, 0x00);
  dv.setUint8(dataRva + 19, 0x11);
  dv.setUint32(dataRva + 20, 3, true);
  encoder.encodeInto("C:\\path\\app.pdb\0", new Uint8Array(bytes.buffer, dataRva + 24));

  const result = await parseDebugDirectory(
    new MockFile(bytes, "debug.bin"),
    [{ name: "DEBUG", rva: debugRva, size: 28 }],
    value => value,
    () => {}
  );

  const entry = expectDefined(result.entry);
  assert.equal(entry.age, 3);
  assert.match(entry.guid, /11223344-5566-7788-aabb-ccddeeff0011/);
  assert.match(entry.path, /app\.pdb/);
});

void test("parseDebugDirectory bounds CodeView reads to header and path chunks", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  const debugRva = 0x40;
  const dataRva = 0x120;
  dv.setUint32(debugRva + 12, 2, true);
  dv.setUint32(debugRva + 16, 0x200000, true);
  dv.setUint32(debugRva + 20, dataRva, true);
  dv.setUint32(debugRva + 24, dataRva, true);
  dv.setUint32(dataRva + 0, 0x53445352, true);
  dv.setUint32(dataRva + 4, 0x11223344, true);
  dv.setUint16(dataRva + 8, 0x5566, true);
  dv.setUint16(dataRva + 10, 0x7788, true);
  dv.setUint8(dataRva + 12, 0xaa);
  dv.setUint8(dataRva + 13, 0xbb);
  dv.setUint8(dataRva + 14, 0xcc);
  dv.setUint8(dataRva + 15, 0xdd);
  dv.setUint8(dataRva + 16, 0xee);
  dv.setUint8(dataRva + 17, 0xff);
  dv.setUint8(dataRva + 18, 0x00);
  dv.setUint8(dataRva + 19, 0x11);
  dv.setUint32(dataRva + 20, 7, true);
  encoder.encodeInto("C:\\tracked\\app.pdb\0", new Uint8Array(bytes.buffer, dataRva + 24));

  const tracked = createSliceTrackingFile(bytes, 0x400000, "debug-bounded-read.bin");
  const result = await parseDebugDirectory(
    tracked.file,
    [{ name: "DEBUG", rva: debugRva, size: 28 }],
    value => value,
    () => {}
  );

  assert.equal(result.entry?.age, 7);
  assert.ok(
    Math.max(...tracked.requests) <= 64,
    `Expected bounded CodeView reads, got requests ${tracked.requests.join(", ")}`
  );
});
