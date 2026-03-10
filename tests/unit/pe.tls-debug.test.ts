"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDebugDirectory } from "../../analyzers/pe/debug-directory.js";
import { parseLoadConfigDirectory } from "../../analyzers/pe/load-config.js";
import { parseTlsDirectory } from "../../analyzers/pe/tls.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";

const encoder = new TextEncoder();

void test("parseDebugDirectory reads CodeView RSDS entry", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  const debugRva = 0x40;
  const dataRva = 0x120;
  // Debug directory entry at 0x40
  dv.setUint32(debugRva + 12, 2, true); // type CodeView
  dv.setUint32(debugRva + 16, 32, true); // size
  dv.setUint32(debugRva + 20, dataRva, true); // AddressOfRawData (RVA)
  dv.setUint32(debugRva + 24, dataRva, true); // PointerToRawData (file offset)
  // RSDS header
  dv.setUint32(dataRva + 0, 0x53445352, true); // RSDS
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
  dv.setUint32(dataRva + 20, 3, true); // age
  encoder.encodeInto("C:\\path\\app.pdb\0", new Uint8Array(bytes.buffer, dataRva + 24));

  const file = new MockFile(bytes, "debug.bin");
  const result = await parseDebugDirectory(
    file,
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

void test("parseLoadConfigDirectory reads 32-bit and 64-bit fields", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  const lcRva = 0x80;
  dv.setUint32(lcRva + 0, 0x80, true); // Size
  dv.setUint32(lcRva + 4, 0x12345678, true);
  dv.setUint16(lcRva + 8, 5, true);
  dv.setUint16(lcRva + 10, 1, true);
  dv.setUint32(lcRva + 0x3c, 0xCAFEBABE, true); // SecurityCookie
  dv.setUint32(lcRva + 0x40, 0x200, true); // SEHandlerTable
  dv.setUint32(lcRva + 0x44, 3, true); // SEHandlerCount
  dv.setUint32(lcRva + 0x50, 0x300, true); // GuardCFFunctionTable
  dv.setUint32(lcRva + 0x54, 2, true);
  dv.setUint32(lcRva + 0x58, 0x1111, true); // GuardFlags

  const file = new MockFile(bytes, "loadcfg.bin");
  const lc = expectDefined(await parseLoadConfigDirectory(
    file,
    [{ name: "LOAD_CONFIG", rva: lcRva, size: 0x5c }],
    value => value,
    () => {},
    false
  ));
  assert.equal(lc.SecurityCookie, 0xCAFEBABE);
  assert.equal(lc.SEHandlerCount, 3);
  assert.equal(lc.GuardCFFunctionCount, 2);
  assert.equal(lc.GuardFlags, 0x1111);

  // 64-bit path
  const bytes64 = new Uint8Array(512).fill(0);
  const dv64 = new DataView(bytes64.buffer);
  dv64.setUint32(0, 0x140, true);
  dv64.setUint32(4, 0x9abcdef0, true);
  dv64.setUint16(8, 10, true);
  dv64.setUint16(10, 2, true);
  dv64.setBigUint64(0x58, 0x1234n, true);
  dv64.setBigUint64(0x60, 0x5678n, true);
  dv64.setBigUint64(0x68, 5n, true);
  dv64.setBigUint64(0x80, 0x9abcn, true);
  dv64.setBigUint64(0x88, 6n, true);
  dv64.setUint32(0x90, 0xbeef, true);
  const lc64 = expectDefined(await parseLoadConfigDirectory(
    new MockFile(bytes64),
    [{ name: "LOAD_CONFIG", rva: 0x10, size: 0x140 }],
    value => (value === 0x10 ? 0 : value),
    () => {},
    true
  ));
  assert.equal(lc64.SEHandlerCount, 5);
  assert.equal(lc64.GuardCFFunctionCount, 6);
  assert.equal(lc64.GuardFlags, 0xbeef);
});

void test("parseTlsDirectory handles 32-bit and 64-bit callbacks", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  const tlsRva = 0x20;
  dv.setUint32(tlsRva + 0, 0x10, true);
  dv.setUint32(tlsRva + 4, 0x20, true);
  dv.setUint32(tlsRva + 8, 0x30, true);
  dv.setUint32(tlsRva + 12, 0x40, true); // callbacks RVA
  dv.setUint32(tlsRva + 16, 4, true);
  dv.setUint32(tlsRva + 20, 0, true);
  dv.setUint32(0x40, 0x1111, true);
  dv.setUint32(0x44, 0); // terminator
  const tls = expectDefined(await parseTlsDirectory(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    value => value,
    () => {},
    false,
    0
  ));
  assert.equal(tls.CallbackCount, 1);
  assert.deepEqual(tls.CallbackRvas, [0x1111]);

  // 64-bit version with callbacks
  const bytes64 = new Uint8Array(512).fill(0);
  const dv64 = new DataView(bytes64.buffer);
  dv64.setBigUint64(0x00, 0x100n, true);
  dv64.setBigUint64(0x08, 0x200n, true);
  dv64.setBigUint64(0x10, 0x300n, true);
  dv64.setBigUint64(0x18, 0x80n, true); // callbacks table RVA (relative to imageBase)
  dv64.setUint32(0x20, 8, true);
  dv64.setUint32(0x24, 0, true);
  // callbacks table at offset 0x80 in file (imageBase 0)
  dv64.setBigUint64(0x80, 0x7000n, true);
  dv64.setBigUint64(0x88, 0n, true);
  const tls64 = expectDefined(await parseTlsDirectory(
    new MockFile(bytes64),
    [{ name: "TLS", rva: 0x10, size: 0x30 }],
    value => (value === 0x10 ? 0 : value),
    () => {},
    true,
    0
  ));
  assert.equal(tls64.CallbackCount, 1);
  assert.deepEqual(tls64.CallbackRvas, [0x7000]);
});

void test("parseTlsDirectory returns null for missing or unmapped TLS directory", async () => {
  const file = new MockFile(new Uint8Array(16));
  assert.equal(await parseTlsDirectory(file, [], value => value, () => {}, false, 0), null);

  assert.equal(await parseTlsDirectory(
    file,
    [{ name: "TLS", rva: 0x20, size: 0x18 }],
    () => null,
    () => {},
    false,
    0
  ), null);
});

void test("parseTlsDirectory returns null for truncated TLS directory headers", async () => {
  const tlsRva = 0x20;
  const truncated32 = new Uint8Array(tlsRva + 0x10).fill(0);
  assert.equal(await parseTlsDirectory(
    new MockFile(truncated32),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    value => value,
    () => {},
    false,
    0
  ), null);

  const truncated64 = new Uint8Array(tlsRva + 0x20).fill(0);
  assert.equal(await parseTlsDirectory(
    new MockFile(truncated64),
    [{ name: "TLS", rva: tlsRva, size: 0x30 }],
    value => value,
    () => {},
    true,
    0
  ), null);
});

void test("parseTlsDirectory skips invalid callback pointers and tolerates out-of-range callback tables", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  const tlsRva = 0x20;
  dv.setUint32(tlsRva + 12, 0x2040, true); // callbacks VA (imageBase 0x2000 + rva 0x40)
  dv.setUint32(0x40, 0x1000, true); // callback VA below imageBase => invalid
  dv.setUint32(0x44, 0, true); // terminator
  const tls = expectDefined(await parseTlsDirectory(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    value => value,
    () => {},
    false,
    0x2000
  ));
  assert.equal(tls.CallbackCount, 0);
  assert.deepEqual(tls.CallbackRvas, []);

  const bytesOutOfRange = new Uint8Array(64).fill(0);
  const dvOutOfRange = new DataView(bytesOutOfRange.buffer);
  dvOutOfRange.setUint32(tlsRva + 12, 0x1000, true);
  const rvaToOff = (rva: number): number => (rva === tlsRva ? tlsRva : bytesOutOfRange.length + 4);
  const tlsOutOfRange = expectDefined(await parseTlsDirectory(
    new MockFile(bytesOutOfRange),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    rvaToOff,
    () => {},
    false,
    0
  ));
  assert.equal(tlsOutOfRange.CallbackCount, 0);
  assert.deepEqual(tlsOutOfRange.CallbackRvas, []);
});
