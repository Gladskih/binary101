import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe } from "../../../../analyzers/pe/index.js";
import { analyzePeEmbeddedResources } from "../../../../analyzers/pe/embedded-resources.js";
import { embeddedResourceFixture, minimalRcc } from "../../../fixtures/embedded-resource-builders.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import type { CoffSymbol } from "../../../../analyzers/coff/debug-types.js";

const symbolPe = () => {
  const fixture = minimalRcc();
  const pe = createBasePe();
  pe.sections = [{ name: { kind: "inline", value: ".rdata" }, virtualSize: fixture.bytes.length,
    virtualAddress: 0, sizeOfRawData: fixture.bytes.length, pointerToRawData: 0, characteristics: 0 }];
  pe.coffDebug = { source: "coff-header", symbolTableOffset: 0, stringTableOffset: null,
    lineNumberBlocks: [], symbols: [
      { name: ".file", value: 0, storageClass: 103, sectionNumber: 0 },
      { name: "qt_resource_struct", value: fixture.tree },
      { name: "qt_resource_name", value: fixture.names },
      { name: "qt_resource_data", value: fixture.data }
    ].map((record, index): CoffSymbol => ({ index, nameSource: "short", sectionNumber: 1,
      type: 0, storageClass: 3, auxiliarySymbolCount: 0, auxiliaryRecords: [], ...record })) };
  return { pe, fixture };
};

void test("integrates named/ordinary GResource, Qt qres and COFF array symbols in generated PE", async () => {
  const file = new MockFile(embeddedResourceFixture("qt-glib.dll"));
  const parsed = await parsePe(file);
  assert.ok(parsed);
  assert.equal(parsed.embeddedResources?.bundles.length, 4);
  assert.deepEqual(parsed.embeddedResources?.issues, []);
  assert.deepEqual(parsed.embeddedResources?.bundles.map(bundle => bundle.resource.format).sort(),
    ["GLib GResource", "GLib GResource", "Qt RCC", "Qt RCC"]);
  const withoutSymbols = { ...parsed };
  delete withoutSymbols.coffDebug;
  assert.equal((await analyzePeEmbeddedResources(file, withoutSymbols))?.bundles.length, 3);
});

void test("associates COFF arrays using file scope and bounded next-symbol ranges", async () => {
  const { pe, fixture } = symbolPe();
  // No section scan: valid symbol evidence still supports compiled arrays without qres.
  const file = new MockFile(fixture.bytes);
  pe.sections[0]!.name.value = ".data";
  const result = await analyzePeEmbeddedResources(file, pe);
  assert.equal(result?.bundles.length, 1);
  const fromSymbols = await analyzePeEmbeddedResources(
    new MockFile(new Uint8Array(fixture.bytes).fill(0, 0, fixture.tree)), pe);
  assert.ok(fromSymbols?.bundles[0]?.evidence.includes("RCC array symbols in COFF file symbol #0"));
  assert.ok(result?.bundles[0]?.resource.entries[1]?.payload);
  pe.sections[0]!.sizeOfRawData -= 1;
  const truncated = await analyzePeEmbeddedResources(file, pe);
  assert.deepEqual(truncated?.bundles, []);
  assert.match(truncated!.issues.join(), /invalid or ambiguous/);
});

void test("retains the COFF table scope when no FILE symbol is available", async () => {
  const { pe, fixture } = symbolPe();
  pe.coffDebug!.symbols.shift();
  fixture.bytes.fill(0, 0, fixture.tree);
  const result = await analyzePeEmbeddedResources(new MockFile(fixture.bytes), pe);
  assert.ok(result?.bundles[0]?.evidence.includes("RCC array symbols in COFF symbol table"));
});

void test("clips COFF next-symbol extents to section raw data despite out-of-section symbols", async () => {
  const { pe, fixture } = symbolPe();
  pe.coffDebug!.symbols.push({ ...pe.coffDebug!.symbols[3]!, name: "outside", value: fixture.bytes.length + 8 });
  fixture.bytes.fill(0, 0, fixture.tree);
  const result = await analyzePeEmbeddedResources(new MockFile(fixture.bytes), pe);
  assert.equal(result?.bundles.length, 1);
  assert.deepEqual(result?.issues, []);
});

void test("does not send negative or overflowing relocated addresses to the PE mapper", async () => {
  const fixture = minimalRcc();
  const bytes = new Uint8Array(fixture.bytes.length + 24);
  bytes.set(fixture.bytes);
  const pe = createBasePe();
  pe.sections = [{ name: { kind: "inline", value: ".data" }, virtualSize: bytes.length,
    virtualAddress: 0, sizeOfRawData: bytes.length, pointerToRawData: 0, characteristics: 0 }];
  const calls: number[] = [];
  pe.rvaToOff = rva => {
    calls.push(rva);
    return rva === 0xffffffff ? fixture.tree : rva >= 0 && rva < bytes.length ? rva : null;
  };
  const view = new DataView(bytes.buffer);
  view.setBigUint64(fixture.bytes.length, 0n, true);
  view.setBigUint64(fixture.bytes.length + 8, pe.opt.ImageBase + 0x100000000n, true);
  view.setBigUint64(fixture.bytes.length + 16, pe.opt.ImageBase + 0xffffffffn, true);
  pe.reloc = { blocks: [{ pageRva: fixture.bytes.length, size: 14, count: 3, entries: [
    { type: 10, offset: 0 }, { type: 10, offset: 8 }, { type: 10, offset: 16 }, { type: 0, offset: 0 }
  ] }], totalEntries: 3 };
  const result = await analyzePeEmbeddedResources(new MockFile(bytes), pe);
  assert.deepEqual(calls, [fixture.bytes.length, fixture.bytes.length + 8, fixture.bytes.length + 16, 0xffffffff]);
  assert.equal(result?.bundles[0]?.evidence.filter(item => item.includes("base relocation")).length, 1);
});

for (const sectionNumber of [-1, 0, 2]) {
  void test(`does not resolve an RCC symbol in invalid COFF section ${sectionNumber}`, async () => {
    const { pe, fixture } = symbolPe();
    pe.coffDebug!.symbols[1]!.sectionNumber = sectionNumber;
    fixture.bytes.fill(0, 0, fixture.tree); // Remove qres; only symbol detection remains.
    assert.equal(await analyzePeEmbeddedResources(new MockFile(fixture.bytes), pe), null);
  });
}

void test("rejects a COFF symbol at the end of its section and handles an absent raw section", async () => {
  const { pe, fixture } = symbolPe();
  fixture.bytes.fill(0, 0, fixture.tree);
  pe.coffDebug!.symbols[1]!.value = fixture.bytes.length;
  assert.equal(await analyzePeEmbeddedResources(new MockFile(fixture.bytes), pe), null);
  pe.sections = [];
  assert.equal(await analyzePeEmbeddedResources(new MockFile(fixture.bytes), pe), null);
});

void test("preserves actual PE absolute-pointer relocation evidence for 32- and 64-bit slots", async () => {
  const fixture = minimalRcc();
  const bytes = new Uint8Array(fixture.bytes.length + 16);
  bytes.set(fixture.bytes);
  const pe = createBasePe();
  pe.sections = [{ name: { kind: "inline", value: ".data" }, virtualSize: bytes.length,
    virtualAddress: 0, sizeOfRawData: bytes.length, pointerToRawData: 0, characteristics: 0 }];
  pe.rvaToOff = rva => rva >= 0 && rva < bytes.length ? rva : null;
  const view = new DataView(bytes.buffer);
  view.setBigUint64(fixture.bytes.length, pe.opt.ImageBase + BigInt(fixture.tree), true);
  view.setUint32(fixture.bytes.length + 8, Number(pe.opt.ImageBase), true);
  view.setUint32(fixture.bytes.length + 12, 0xfeedbeef, true);
  pe.reloc = { blocks: [{ pageRva: fixture.bytes.length, size: 12, count: 2,
    entries: [{ type: 10, offset: 0 }, { type: 3, offset: 8 }] }], totalEntries: 2 };
  const result = await analyzePeEmbeddedResources(new MockFile(bytes), pe);
  assert.equal(result?.bundles[0]?.evidence.filter(item => item.includes("base relocation")).length, 2);
});

void test("ignores unsupported, unmapped, truncated and out-of-image PE relocation pointers", async () => {
  const fixture = minimalRcc();
  const pe = createBasePe();
  pe.sections = [{ name: { kind: "inline", value: ".data" }, virtualSize: fixture.bytes.length,
    virtualAddress: 0, sizeOfRawData: fixture.bytes.length, pointerToRawData: 0, characteristics: 0 }];
  pe.reloc = { blocks: [{ pageRva: 0, size: 8, count: 4, entries: [
    { type: 0, offset: 0 }, { type: 10, offset: fixture.bytes.length },
    { type: 3, offset: fixture.bytes.length - 1 }, { type: 10, offset: 0 }
  ] }], totalEntries: 4 };
  pe.rvaToOff = rva => rva === fixture.bytes.length ? null : rva;
  const result = await analyzePeEmbeddedResources(new MockFile(fixture.bytes), pe);
  assert.equal(result?.bundles[0]?.evidence.length, 1);
  const rom = await analyzePeEmbeddedResources(new MockFile(fixture.bytes), { ...pe, opt: null });
  assert.equal(rom?.bundles[0]?.evidence.length, 1);
});

void test("ignores an in-image relocation target that has no file-backed mapping", async () => {
  const fixture = minimalRcc();
  const bytes = new Uint8Array(fixture.bytes.length + 8);
  bytes.set(fixture.bytes);
  const pe = createBasePe();
  new DataView(bytes.buffer).setBigUint64(fixture.bytes.length, pe.opt.ImageBase + 0x1000n, true);
  pe.sections = [{ name: { kind: "inline", value: ".data" }, virtualSize: bytes.length,
    virtualAddress: 0, sizeOfRawData: bytes.length, pointerToRawData: 0, characteristics: 0 }];
  pe.reloc = { blocks: [{ pageRva: fixture.bytes.length, size: 10, count: 1,
    entries: [{ type: 10, offset: 0 }] }], totalEntries: 1 };
  const calls: number[] = [];
  pe.rvaToOff = rva => {
    calls.push(rva);
    return rva === fixture.bytes.length ? fixture.bytes.length : null;
  };
  const result = await analyzePeEmbeddedResources(new MockFile(bytes), pe);
  assert.deepEqual(calls, [fixture.bytes.length, 0x1000]);
  assert.equal(result?.bundles[0]?.evidence.length, 1);
});
