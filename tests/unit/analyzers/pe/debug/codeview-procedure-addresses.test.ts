import assert from "node:assert/strict";
import { test } from "node:test";
import { createCodeViewProcedureResolver } from "../../../../../analyzers/pe/debug/codeview-procedure-addresses.js";
import { codeViewAddressInfo, codeViewAddressMap,
  codeViewAddressSections } from "../../../../fixtures/pe-codeview-procedure-addresses.js";
import type { LegacyCodeViewProcedure } from "../../../../../analyzers/pe/debug/legacy-codeview-procedure-symbols.js";

const procedure = (segment = 1, offset = 16, codeLength = 32): LegacyCodeViewProcedure => ({
  referenceKind: "typeIndex", storedLocation: { segment, offset }, codeLength
});

void test("CodeView resolves logical segment frame and displacement before the stored procedure offset", () => {
  const resolve = createCodeViewProcedureResolver(codeViewAddressInfo(), codeViewAddressSections());

  assert.deepEqual(resolve(0, procedure()), { rva: 0x3030, section: 2 });
  assert.deepEqual(resolve(0, procedure(1, 32, 32)), { rva: 0x3040, section: 2 });
  assert.deepEqual(resolve(0, procedure(1, 63, 0)), { rva: 0x305f, section: 2 });
  assert.match(resolve(0, procedure(1, 33, 32)).reason!, /logical segment bounds/);
  assert.match(resolve(0, procedure(1, 64, 0)).reason!, /logical segment bounds/);
});

void test("CodeView without a segment map uses PE section indices with virtual bounds", () => {
  const info = codeViewAddressInfo();
  info.directories[0]!.subsections = [];
  const resolve = createCodeViewProcedureResolver(info, codeViewAddressSections());

  assert.deepEqual(resolve(0, procedure()), { rva: 0x1010, section: 1 });
  assert.deepEqual(resolve(0, procedure(2, 224, 32)), { rva: 0x30e0, section: 2 });
  assert.match(resolve(0, procedure(1, 255, 2)).reason!, /PE section bounds/);
  assert.match(resolve(0, procedure(1, 256, 0)).reason!, /PE section bounds/);
});

for (const [field, value, reason] of [
  ["flags", 0x30d, /absolute|selector/], ["flags", 0x100d, /group|selector/],
  ["flags", 0x0d, /selector/], ["flags", 0x105, /32-bit/],
  ["flags", 0x90d, /unsupported/], ["overlay", 1, /overlay/i],
  ["group", 1, /group/], ["frame", 0, /section index/], ["frame", 3, /section index/],
  ["offset", 240, /PE section bounds/], ["size", 0, /logical segment bounds/]
] as const) {
  void test(`CodeView rejects an unsupported or out-of-bounds segment descriptor ${field}=${value}`, () => {
    const info = codeViewAddressInfo();
    const map = info.directories[0]!.subsections[0]!.data;
    assert.ok(map?.kind === "segmentMap");
    map.segments[0]![field] = value;

    assert.match(createCodeViewProcedureResolver(info, codeViewAddressSections())(0, procedure()).reason!, reason);
  });
}

void test("CodeView does not replace an absent or damaged map with an invented section mapping", () => {
  const info = codeViewAddressInfo();
  const map = info.directories[0]!.subsections[0]!;
  delete map.data;

  assert.match(createCodeViewProcedureResolver(info, codeViewAddressSections())(0, procedure()).reason!, /not decoded/);
  map.data = codeViewAddressMap();
  map.data.logicalCount = 2;
  assert.match(createCodeViewProcedureResolver(info, codeViewAddressSections())(0, procedure()).reason!, /logical segment count/);
  map.data.logicalCount = 0;
  assert.match(createCodeViewProcedureResolver(info, codeViewAddressSections())(0, procedure()).reason!, /logical segment index/);
});

void test("CodeView duplicate maps are ambiguous while shared physical subsection decodes are reused", () => {
  const info = codeViewAddressInfo();
  info.directories[0]!.subsections.push({ ...info.directories[0]!.subsections[0]! });
  assert.deepEqual(createCodeViewProcedureResolver(info, codeViewAddressSections())(0, procedure()),
    { rva: 0x3030, section: 2 });
  info.directories[0]!.subsections[1]!.data = codeViewAddressMap();

  assert.match(createCodeViewProcedureResolver(info, codeViewAddressSections())(0, procedure()).reason!, /multiple/);
});

void test("CodeView incremental directories inherit the last map without using a future generation", () => {
  const info = codeViewAddressInfo();
  info.directories.unshift({ flags: 0, subsections: [] });
  info.directories.push({ flags: 0, subsections: [] });
  const replacement = codeViewAddressMap();
  replacement.segments[0]!.frame = 1;
  info.directories.push({ flags: 0, subsections: [{ ...info.directories[1]!.subsections[0]!, data: replacement }] });
  const resolve = createCodeViewProcedureResolver(info, codeViewAddressSections());

  assert.deepEqual(resolve(0, procedure()), { rva: 0x1010, section: 1 });
  assert.deepEqual(resolve(1, procedure()), { rva: 0x3030, section: 2 });
  assert.deepEqual(resolve(2, procedure()), { rva: 0x3030, section: 2 });
  assert.deepEqual(resolve(3, procedure()), { rva: 0x1030, section: 1 });
});

for (const type of [7, 8]) {
  void test(`CodeView refuses current-image RVAs with OMAP debug type ${type}`, () => {
    const resolve = createCodeViewProcedureResolver(codeViewAddressInfo(), codeViewAddressSections(), [{ type }]);

    assert.match(resolve(0, procedure()).reason!, /OMAP.*original section/);
  });
}

void test("CodeView reports missing fields and invalid references without throwing", () => {
  const resolve = createCodeViewProcedureResolver(codeViewAddressInfo(), codeViewAddressSections());

  assert.match(resolve(0, { referenceKind: "typeIndex" }).reason!, /location or code length/);
  assert.match(resolve(0, procedure(0)).reason!, /invalid/);
  assert.match(resolve(0, procedure(65536)).reason!, /invalid/);
  assert.match(resolve(0, procedure(1, -1)).reason!, /invalid/);
  assert.match(resolve(0, procedure(1, 0, 1.5)).reason!, /invalid/);
  assert.match(resolve(99, procedure()).reason!, /directory/);
  assert.match(resolve(0, procedure(2)).reason!, /logical segment index/);
});

void test("CodeView requires a uniquely mapped PE range and bounded 32-bit section arithmetic", () => {
  const sections = codeViewAddressSections();
  sections[0]!.virtualAddress = 0x3040;
  assert.match(createCodeViewProcedureResolver(codeViewAddressInfo(), sections)(0, procedure()).reason!, /overlap/);
  sections[0]!.virtualAddress = 0x1000;
  sections[1]!.virtualAddress = 0xfffffff0;
  assert.match(createCodeViewProcedureResolver(codeViewAddressInfo(), sections)(0, procedure()).reason!, /32-bit/);
  sections[1]!.virtualAddress = Number.NaN;
  assert.match(createCodeViewProcedureResolver(codeViewAddressInfo(), sections)(0, procedure()).reason!, /invalid PE section/);
});

void test("CodeView handles zero VirtualSize using raw size and rejects legacy frame-map assumptions", () => {
  const sections = codeViewAddressSections();
  sections[1]!.virtualSize = 0;
  assert.deepEqual(createCodeViewProcedureResolver(codeViewAddressInfo(), sections)(0, procedure()),
    { rva: 0x3030, section: 2 });
  const info = codeViewAddressInfo();
  info.directories[0]!.subsections.push({ type: 0x12c, module: 0xffff, offset: 32, size: 4,
    data: { kind: "frameMap", frames: [1] } });
  assert.match(createCodeViewProcedureResolver(info, sections)(0, procedure()).reason!, /frame map/);
  info.signature = "NB02";
  assert.match(createCodeViewProcedureResolver(info, sections)(0, procedure()).reason!, /C7/);
});

void test("CodeView rejects invalid descriptor displacements before section arithmetic", () => {
  const info = codeViewAddressInfo();
  const map = info.directories[0]!.subsections[0]!.data;
  assert.ok(map?.kind === "segmentMap");
  map.segments[0]!.offset = Number.NaN;

  assert.match(createCodeViewProcedureResolver(info, codeViewAddressSections())(0, procedure()).reason!, /displacement/);
});

void test("Empty neighboring PE sections cannot overlap a procedure range", () => {
  const sections = codeViewAddressSections();
  sections[0]!.virtualAddress = 0x3040;
  sections[0]!.virtualSize = 0;
  sections[0]!.sizeOfRawData = 0;

  assert.deepEqual(createCodeViewProcedureResolver(codeViewAddressInfo(), sections)(0, procedure()),
    { rva: 0x3030, section: 2 });
});

void test("CodeView preserves the last valid 32-bit RVA and segment 65535", () => {
  const info = codeViewAddressInfo();
  info.directories[0]!.subsections = [];
  const sections = codeViewAddressSections();
  sections[1]!.virtualAddress = 0xfffffff0;
  sections[1]!.virtualSize = 16;
  assert.deepEqual(createCodeViewProcedureResolver(info, sections)(0, procedure(2, 15, 1)),
    { rva: 0xffffffff, section: 2 });
  assert.match(createCodeViewProcedureResolver(info, sections)(0, procedure(65535)).reason!, /section index/);
});

for (const virtualAddress of [0x2f30, 0x3050]) {
  void test(`CodeView accepts neighboring sections touching a procedure boundary at ${virtualAddress}`, () => {
    const sections = codeViewAddressSections();
    sections[0]!.virtualAddress = virtualAddress;

    assert.deepEqual(createCodeViewProcedureResolver(codeViewAddressInfo(), sections)(0, procedure()),
      { rva: 0x3030, section: 2 });
  });
}

for (const logicalCount of [-1, 0.5]) {
  void test(`CodeView rejects invalid logical segment counts ${logicalCount}`, () => {
    const info = codeViewAddressInfo();
    const map = info.directories[0]!.subsections[0]!.data;
    assert.ok(map?.kind === "segmentMap");
    map.logicalCount = logicalCount;

    assert.match(createCodeViewProcedureResolver(info, codeViewAddressSections())(0, procedure()).reason!, /logical segment count/);
  });
}

void test("CodeView ignores unrelated subsections and debug types but rejects a partially decoded map set", () => {
  const info = codeViewAddressInfo();
  info.directories[0]!.subsections.push({ type: 0x128, module: 0xffff, offset: 32, size: 4,
    data: { kind: "libraries", names: ["library.lib"] } });
  assert.deepEqual(createCodeViewProcedureResolver(info, codeViewAddressSections(), [{ type: 2 }])(0, procedure()),
    { rva: 0x3030, section: 2 });
  info.directories[0]!.subsections.push({ type: 0x12d, module: 0xffff, offset: 40, size: 4 });

  assert.match(createCodeViewProcedureResolver(info, codeViewAddressSections())(0, procedure()).reason!, /not decoded/);
});
