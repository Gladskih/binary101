"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildResourceTree } from "../../analyzers/pe/resources/core.js";
import { parseImportDirectory64 } from "../../analyzers/pe/imports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();
void test("buildResourceTree walks a small resource directory", async () => {
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

  const tree = expectDefined(await buildResourceTree(
    new MockFile(bytes),
    [{ name: "RESOURCE", rva: base, size: 0x80 }],
    value => value
  ));

  assert.equal(tree.top.length, 1);
  const topEntry = expectDefined(tree.top[0]);
  assert.equal(topEntry.leafCount, 1);
  const detailEntry = expectDefined(tree.detail[0]);
  const lang = expectDefined(expectDefined(detailEntry.entries[0]).langs[0]);
  assert.equal(lang.size, 16);
});

void test("parseImportDirectory supports 64-bit imports path", async () => {
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

  const { entries: imports } = await parseImportDirectory64(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => value
  );
  assert.equal(imports.length, 1);
  const firstImport = expectDefined(imports[0]);
  assert.equal(firstImport.functions.length, 2);
  assert.deepEqual(firstImport.functions[0], { hint: 0x77, name: "RegOpenKey" });
  assert.deepEqual(firstImport.functions[1], { ordinal: 5 });
});
