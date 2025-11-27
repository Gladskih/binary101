"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildResourceTree } from "../../analyzers/pe/resources-core.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const setU16 = (view: DataView, off: number, value: number): void => view.setUint16(off, value, true);
const setU32 = (view: DataView, off: number, value: number): void => view.setUint32(off, value, true);

void test("buildResourceTree returns null when resource directory is missing or unmapped", async () => {
  const file = new MockFile(new Uint8Array(0));
  const noDir = await buildResourceTree(file, [], () => 0, () => {});
  assert.strictEqual(noDir, null);

  const dataDirs = [{ name: "RESOURCE", rva: 0x200, size: 32 }];
  const unmapped = await buildResourceTree(file, dataDirs, () => null, () => {});
  assert.strictEqual(unmapped, null);
});

void test("buildResourceTree parses nested resource directories and skips truncated labels", async () => {
  const bytes = new Uint8Array(0x130).fill(0);
  const dv = new DataView(bytes.buffer);

  // Root directory: 1 named, 1 ID entry.
  setU16(dv, 12, 1);
  setU16(dv, 14, 1);
  // Entry 0: ID type (ICON) -> subdir at 0x20.
  setU32(dv, 16, 0x00000003);
  setU32(dv, 20, 0x80000020);
  // Entry 1: name-based type with out-of-bounds label (forces empty string).
  setU32(dv, 24, 0x80000120);
  setU32(dv, 28, 0x00000000);

  // Name directory at 0x20: 1 named entry pointing to language dir.
  setU16(dv, 0x20 + 12, 1);
  setU16(dv, 0x20 + 14, 0);
  setU32(dv, 0x20 + 16, 0x80000040); // label at 0x40
  setU32(dv, 0x20 + 20, 0x80000060); // lang dir at 0x60

  // UCS-2 label "Test" at 0x40.
  setU16(dv, 0x40, 4);
  const label = new Uint8Array([0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00]);
  bytes.set(label, 0x42);

  // Language directory at 0x60: 1 ID entry pointing to data entry.
  setU16(dv, 0x60 + 12, 0);
  setU16(dv, 0x60 + 14, 1);
  setU32(dv, 0x60 + 16, 0x00000409); // lang 0x409
  setU32(dv, 0x60 + 20, 0x00000080);

  // Data entry at 0x80.
  setU32(dv, 0x80, 0x00002000); // DataRVA
  setU32(dv, 0x84, 0x00000010); // Size
  setU32(dv, 0x88, 0x000004b0); // CodePage
  setU32(dv, 0x8c, 0x00000000); // Reserved

  const dataDirs = [{ name: "RESOURCE", rva: 0x00000001, size: 0x120 }];
  const coverage: Array<{ label: string; start: number; size: number }> = [];
  const tree = await buildResourceTree(
    new MockFile(bytes, "pe-resources.bin", "application/octet-stream"),
    dataDirs,
    () => 0,
    (label, start, size) => coverage.push({ label, start, size })
  );

  const definedTree = expectDefined(tree);
  assert.strictEqual(definedTree.top.length, 2);
  assert.deepStrictEqual(definedTree.top[0], { typeName: "ICON", kind: "id", leafCount: 1 });
  assert.deepStrictEqual(definedTree.top[1], { typeName: "", kind: "name", leafCount: 0 });
  assert.ok(definedTree.detail.find(d => d.typeName === "ICON"));

  const iconDetail = expectDefined(definedTree.detail.find(d => d.typeName === "ICON"));
  const iconEntry = expectDefined(iconDetail.entries[0]);
  const iconLang = expectDefined(iconEntry.langs[0]);
  assert.strictEqual(iconEntry.name, "Test");
  assert.deepStrictEqual(iconLang, {
    lang: 0x409,
    size: 0x10,
    codePage: 0x4b0,
    dataRVA: 0x2000,
    reserved: 0
  });

  assert.strictEqual(expectDefined(coverage[0]).label, "RESOURCE directory");
});
