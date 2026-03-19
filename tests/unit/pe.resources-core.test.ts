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

void test("buildResourceTree ignores directory entries that lie past the declared resource span", async () => {
  const bytes = new Uint8Array(0x40).fill(0);
  const dv = new DataView(bytes.buffer);

  setU16(dv, 12, 0);
  setU16(dv, 14, 1);
  // The resource data directory declares only the 16-byte root header.
  setU32(dv, 16, 3);
  // High bit marks a subdirectory and the low bits point to relative offset 0x20, which lies past dir.size=16.
  setU32(dv, 20, 0x80000020);

  const tree = expectDefined(await buildResourceTree(
    new MockFile(bytes, "resource-oob-root.bin"),
    [{ name: "RESOURCE", rva: 1, size: 16 }],
    () => 0,
    () => {}
  ));

  assert.deepStrictEqual(tree.top, []);
  assert.deepStrictEqual(tree.detail, []);
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

void test("buildResourceTree accepts data entries that end exactly at the resource boundary", async () => {
  const bytes = new Uint8Array(0x70).fill(0);
  const dv = new DataView(bytes.buffer);

  setU16(dv, 12, 0);
  setU16(dv, 14, 1);
  setU32(dv, 16, 0x00000003);
  setU32(dv, 20, 0x80000020);

  setU16(dv, 0x20 + 12, 0);
  setU16(dv, 0x20 + 14, 1);
  setU32(dv, 0x20 + 16, 0x00000001);
  setU32(dv, 0x20 + 20, 0x80000040);

  setU16(dv, 0x40 + 12, 0);
  setU16(dv, 0x40 + 14, 1);
  setU32(dv, 0x40 + 16, 0x00000409);
  setU32(dv, 0x40 + 20, 0x00000060);

  setU32(dv, 0x60 + 0, 0x00002000);
  setU32(dv, 0x60 + 4, 0x00000010);
  setU32(dv, 0x60 + 8, 0x000004b0);
  setU32(dv, 0x60 + 12, 0x00000000);

  const tree = await buildResourceTree(
    new MockFile(bytes, "resource-boundary.bin"),
    [{ name: "RESOURCE", rva: 1, size: bytes.length }],
    () => 0,
    () => {}
  );

  const definedTree = expectDefined(tree);
  assert.deepStrictEqual(definedTree.top, [{ typeName: "ICON", kind: "id", leafCount: 1 }]);
  const iconDetail = expectDefined(definedTree.detail[0]);
  const iconEntry = expectDefined(iconDetail.entries[0]);
  assert.strictEqual(expectDefined(iconEntry.langs[0]).dataRVA, 0x2000);
});

void test("buildResourceTree walks a small resource directory", async () => {
  const base = 0x10;
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  setU16(dv, base + 12, 0);
  setU16(dv, base + 14, 1);
  setU32(dv, base + 16, 3);
  setU32(dv, base + 20, 0x80000020);

  const nameDir = base + 0x20;
  setU16(dv, nameDir + 12, 0);
  setU16(dv, nameDir + 14, 1);
  setU32(dv, nameDir + 16, 1);
  setU32(dv, nameDir + 20, 0x80000040);

  const langDir = base + 0x40;
  setU16(dv, langDir + 12, 0);
  setU16(dv, langDir + 14, 1);
  setU32(dv, langDir + 16, 0);
  setU32(dv, langDir + 20, 0x00000060);

  const dataEntry = base + 0x60;
  setU32(dv, dataEntry + 0, 0x1000);
  setU32(dv, dataEntry + 4, 16);
  setU32(dv, dataEntry + 8, 1252);
  setU32(dv, dataEntry + 12, 0);

  const tree = expectDefined(await buildResourceTree(
    new MockFile(bytes),
    [{ name: "RESOURCE", rva: base, size: 0x80 }],
    value => value,
    () => {}
  ));

  assert.equal(tree.top.length, 1);
  const topEntry = expectDefined(tree.top[0]);
  assert.equal(topEntry.leafCount, 1);
  const detailEntry = expectDefined(tree.detail[0]);
  const lang = expectDefined(expectDefined(detailEntry.entries[0]).langs[0]);
  assert.equal(lang.size, 16);
});
