"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDebugDirectory, parseLoadConfigDirectory } from "../../analyzers/pe/debug-loadcfg.js";
import { parseTlsDirectory } from "../../analyzers/pe/tls.js";
import { buildResourceTree } from "../../analyzers/pe/resources-core.js";
import { parseImportDirectory } from "../../analyzers/pe/imports.js";
import { MockFile } from "../helpers/mock-file.mjs";

const encoder = new TextEncoder();

test("parseDebugDirectory reads CodeView RSDS entry", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  const debugRva = 0x40;
  const dataRva = 0x120;
  // Debug directory entry at 0x40
  dv.setUint32(debugRva + 12, 2, true); // type CodeView
  dv.setUint32(debugRva + 16, 32, true); // size
  dv.setUint32(debugRva + 20, dataRva, true); // pointer
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

  assert.ok(result.entry);
  assert.equal(result.entry.age, 3);
  assert.match(result.entry.guid, /11223344-5566-7788-aabb-ccddeeff0011/);
  assert.match(result.entry.path, /app\.pdb/);
});

test("parseLoadConfigDirectory reads 32-bit and 64-bit fields", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  const lcRva = 0x80;
  dv.setUint32(lcRva + 0, 0x80, true); // Size
  dv.setUint32(lcRva + 4, 0x12345678, true);
  dv.setUint16(lcRva + 8, 5, true);
  dv.setUint16(lcRva + 10, 1, true);
  dv.setUint32(lcRva + 0x34, 0xCAFEBABE, true); // SecurityCookie
  dv.setUint32(lcRva + 0x40, 0x200, true); // SEHandlerTable
  dv.setUint32(lcRva + 0x44, 3, true); // SEHandlerCount
  dv.setUint32(lcRva + 0x48, 0x300, true); // GuardCFFunctionTable
  dv.setUint32(lcRva + 0x4c, 2, true);
  dv.setUint32(lcRva + 0x50, 0x1111, true); // GuardFlags

  const file = new MockFile(bytes, "loadcfg.bin");
  const lc = await parseLoadConfigDirectory(
    file,
    [{ name: "LOAD_CONFIG", rva: lcRva, size: 0x54 }],
    value => value,
    () => {},
    false
  );
  assert.ok(lc);
  assert.equal(lc.SecurityCookie, 0xCAFEBABE);
  assert.equal(lc.SEHandlerCount, 3);
  assert.equal(lc.GuardCFFunctionCount, 2);
  assert.equal(lc.GuardFlags, 0x1111);

  // 64-bit path
  const bytes64 = new Uint8Array(512).fill(0);
  const dv64 = new DataView(bytes64.buffer);
  dv64.setUint32(0, 0x90, true);
  dv64.setUint32(4, 0x9abcdef0, true);
  dv64.setUint16(8, 10, true);
  dv64.setUint16(10, 2, true);
  dv64.setBigUint64(0x40, 0x1234n, true);
  dv64.setBigUint64(0x58, 0x5678n, true);
  dv64.setUint32(0x60, 5, true);
  dv64.setBigUint64(0x68, 0x9abcn, true);
  dv64.setUint32(0x70, 6, true);
  dv64.setUint32(0x74, 0xbeef, true);
  const lc64 = await parseLoadConfigDirectory(
    new MockFile(bytes64),
    [{ name: "LOAD_CONFIG", rva: 0x10, size: 0x90 }],
    value => (value === 0x10 ? 0 : value),
    () => {},
    true
  );
  assert.ok(lc64);
  assert.equal(lc64.SEHandlerCount, 5);
  assert.equal(lc64.GuardCFFunctionCount, 6);
  assert.equal(lc64.GuardFlags, 0xbeef);
});

test("parseTlsDirectory handles 32-bit and 64-bit callbacks", async () => {
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
  const tls = await parseTlsDirectory(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    value => value,
    () => {},
    false,
    0
  );
  assert.ok(tls);
  assert.equal(tls.CallbackCount, 0); // 32-bit path doesn't enumerate

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
  const tls64 = await parseTlsDirectory(
    new MockFile(bytes64),
    [{ name: "TLS", rva: 0x10, size: 0x30 }],
    value => (value === 0x10 ? 0 : value),
    () => {},
    true,
    0
  );
  assert.ok(tls64);
  assert.equal(tls64.CallbackCount, 1);
});

test("buildResourceTree walks a small resource directory", async () => {
  const base = 0x10;
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  // Root: 1 ID entry
  dv.setUint16(base + 12, 0, true);
  dv.setUint16(base + 14, 1, true);
  dv.setUint32(base + 16, 3, true); // type id = 3 (ICON), subdir flag later
  dv.setUint32(base + 20, 0x80000020, true); // subdir at 0x20
  // Name dir (relative to base)
  const nameDir = base + 0x20;
  dv.setUint16(nameDir + 12, 0, true);
  dv.setUint16(nameDir + 14, 1, true);
  dv.setUint32(nameDir + 16, 1, true); // id 1
  dv.setUint32(nameDir + 20, 0x80000040, true); // subdir at 0x40
  // Lang dir
  const langDir = base + 0x40;
  dv.setUint16(langDir + 12, 0, true);
  dv.setUint16(langDir + 14, 1, true);
  dv.setUint32(langDir + 16, 0, true); // lang id 0
  dv.setUint32(langDir + 20, 0x00000060, true); // data entry at 0x60
  // Data entry
  const dataEntry = base + 0x60;
  dv.setUint32(dataEntry + 0, 0x1000, true); // DataRVA
  dv.setUint32(dataEntry + 4, 16, true); // Size
  dv.setUint32(dataEntry + 8, 1252, true); // CodePage
  dv.setUint32(dataEntry + 12, 0, true); // Reserved

  const tree = await buildResourceTree(
    new MockFile(bytes),
    [{ name: "RESOURCE", rva: base, size: 0x80 }],
    value => value,
    () => {}
  );

  assert.ok(tree);
  assert.equal(tree.top.length, 1);
  assert.equal(tree.top[0].leafCount, 1);
  assert.equal(tree.detail[0].entries[0].langs[0].size, 16);
});

test("parseImportDirectory supports 64-bit imports path", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 0x40;
  dv.setUint32(impBase + 0, 0, true); // original thunk unused
  dv.setUint32(impBase + 12, 0x80, true); // name RVA
  dv.setUint32(impBase + 16, 0x120, true); // firstThunk RVA
  encoder.encodeInto("ADVAPI32.dll\0", new Uint8Array(bytes.buffer, 0x80));
  // FirstThunk table (64-bit values)
  dv.setBigUint64(0x120 + 0, 0x180n, true); // hint/name RVA
  dv.setBigUint64(0x120 + 8, 0x8000000000000005n, true); // ordinal
  dv.setBigUint64(0x120 + 16, 0n, true);
  dv.setUint16(0x180, 0x0077, true);
  encoder.encodeInto("RegOpenKey\0", new Uint8Array(bytes.buffer, 0x182));

  const imports = await parseImportDirectory(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => value,
    () => {},
    true
  );
  assert.equal(imports.length, 1);
  assert.equal(imports[0].functions.length, 2);
  assert.deepEqual(imports[0].functions[0], { hint: 0x77, name: "RegOpenKey" });
  assert.deepEqual(imports[0].functions[1], { ordinal: 5 });
});
