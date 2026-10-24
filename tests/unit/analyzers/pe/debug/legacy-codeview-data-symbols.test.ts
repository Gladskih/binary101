import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewSymbols } from "../../../../../analyzers/pe/debug/legacy-codeview-symbols.js";
import { isPeWindowsParseResult, parsePe } from "../../../../../analyzers/pe/index.js";
import { legacyReader } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewDataSymbol } from "../../../../fixtures/pe-codeview-data-symbols.js";
import { createPeWithCodeViewDataSymbols } from "../../../../fixtures/pe-codeview-data-symbols-file.js";

void test("PE debug integration keeps data symbol metadata in the decoded symbol stream", async () => {
  const parsed = await parsePe(createPeWithCodeViewDataSymbols());
  assert.ok(parsed && isPeWindowsParseResult(parsed));
  const section = parsed.debug?.entries?.[0]?.legacyCodeView?.directories[0]?.subsections
    .find(value => value.data?.kind === "symbols");
  assert.equal(section?.data?.kind, "symbols");
  if (section?.data?.kind !== "symbols") return;
  assert.deepEqual(section.data.records.filter(record => record.data).map(record => ({
    name: record.name, kind: record.data?.kind, typeIndex: record.data?.typeIndex,
    location: record.data?.location, codeLength: record.data?.codeLength
  })), [
    { name: "global_value", kind: "data", typeIndex: 0x74, location: { segment: 1, offset: 0x123 }, codeLength: undefined },
    { name: "published_function", kind: "public", typeIndex: undefined,
      location: { segment: 1, offset: 0x234 }, codeLength: undefined },
    { name: "local_block", kind: "block", typeIndex: undefined,
      location: { segment: 1, offset: 0x300 }, codeLength: 160 }
  ]);
});

void test("CodeView narrow, ST and SZ data symbols preserve their type and stored location", async () => {
  const narrow = codeViewDataSymbol(0x0201, [1, 76], 0xd5, 0x1234);
  const narrowGlobal = codeViewDataSymbol(0x0202, [1, 71], 0xd5, 0x5678);
  const st = codeViewDataSymbol(0x1008, [3, 71, 108, 111]);
  const sz = codeViewDataSymbol(0x110c, [...new TextEncoder().encode("é"), 0]);
  const bytes = [...narrow, ...narrowGlobal, ...st, ...sz];
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

  assert.deepEqual(parsed.records.map(record => ({ type: record.type, name: record.name, data: record.data })), [
    { type: 0x0201, name: "L", data: { kind: "data", typeIndex: 0x1234,
      location: { segment: 9, offset: 0x1234 } } },
    { type: 0x0202, name: "G", data: { kind: "data", typeIndex: 0x5678,
      location: { segment: 9, offset: 0x1234 } } },
    { type: 0x1008, name: "Glo", data: { kind: "data", typeIndex: 0x12345678,
      location: { segment: 9, offset: 0x1234 } } },
    { type: 0x110c, name: "é", data: { kind: "data", typeIndex: 0x12345678,
      location: { segment: 9, offset: 0x1234 } } }
  ]);
  assert.deepEqual(warnings, []);
});

void test("CodeView public symbol variants retain public flags and stored location", async () => {
  const records = [
    codeViewDataSymbol(0x0203, [3, 80, 117, 98]),
    codeViewDataSymbol(0x1009, [3, 83, 84, 80], 0x0f),
    codeViewDataSymbol(0x110e, [...new TextEncoder().encode("SZP"), 0], 0x8000000f)
  ];
  const bytes = records.flat();
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes), 0, bytes.length);

  assert.deepEqual(parsed.records.map(record => ({ type: record.type, name: record.name, data: record.data })), [
    { type: 0x0203, name: "Pub", data: { kind: "public", typeIndex: 0x5678,
      location: { segment: 9, offset: 0x1234 } } },
    { type: 0x1009, name: "STP", data: { kind: "public", location: { segment: 9, offset: 0x1234 }, publicFlags: 0x0f } },
    { type: 0x110e, name: "SZP", data: { kind: "public", location: { segment: 9, offset: 0x1234 },
      publicFlags: 0x8000000f } }
  ]);
});

void test("CodeView data type references and fields match unchanged cvdump output", async () => {
  // clang-cl 22.1.6 /Zi plus cvdump 14.00.23611 reported global_data and
  // local_data as T_INT4 index 0x74 at 0000:00000000.
  const global = codeViewDataSymbol(0x110d, [103, 108, 111, 98, 97, 108, 95, 100, 97, 116, 97, 0],
    0xd5, 0x74, 0, 0);
  const local = codeViewDataSymbol(0x110c, [108, 111, 99, 97, 108, 95, 100, 97, 116, 97, 0],
    0xd5, 0x74, 0, 0);
  const parsed = await readLegacyCodeViewSymbols(legacyReader([...global, ...local]), 0,
    global.length + local.length);

  assert.deepEqual(parsed.records.map(record => ({ name: record.name, data: record.data })), [
    { name: "global_data", data: { kind: "data", typeIndex: 0x74,
      location: { segment: 0, offset: 0 } } },
    { name: "local_data", data: { kind: "data", typeIndex: 0x74,
      location: { segment: 0, offset: 0 } } }
  ]);
});

void test("CodeView blocks and labels preserve lengths, raw scope references and flags", async () => {
  const block = codeViewDataSymbol(0x1103, [...new TextEncoder().encode("Block"), 0]);
  const label = codeViewDataSymbol(0x1105, [...new TextEncoder().encode("Label"), 0]);
  const parsed = await readLegacyCodeViewSymbols(legacyReader([...block, ...label]), 0,
    block.length + label.length);

  assert.deepEqual(parsed.records, [
    { type: 0x1103, name: "Block", data: { kind: "block", location: { segment: 9, offset: 0x1234 }, codeLength: 160,
      scopeOffsets: { parent: 16, end: 32 } } },
    { type: 0x1105, name: "Label", data: { kind: "label", location: { segment: 9, offset: 0x1234 }, flags: 0xd5 } }
  ]);
});

void test("CodeView ST block and label variants retain their Pascal names", async () => {
  const block = codeViewDataSymbol(0x0207, [5, 83, 84, 66, 108, 107]);
  const label = codeViewDataSymbol(0x0209, [5, 83, 84, 76, 97, 98]);
  const parsed = await readLegacyCodeViewSymbols(legacyReader([...block, ...label]), 0,
    block.length + label.length);

  assert.deepEqual(parsed.records.map(record => record.name), ["STBlk", "STLab"]);
});

void test("CodeView symbols salvage complete fixed metadata after truncated names", async () => {
  const data = codeViewDataSymbol(0x110c, [65, 0xff]);
  const label = codeViewDataSymbol(0x1105, [0xff, 0]);
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader([...data, ...label], warnings), 0,
    data.length + label.length);

  assert.deepEqual(parsed.records.map(record => record.data), [
    { kind: "data", typeIndex: 0x12345678, location: { segment: 9, offset: 0x1234 } },
    { kind: "label", location: { segment: 9, offset: 0x1234 }, flags: 0xd5 }
  ]);
  assert.equal(warnings.length, 2);
  assert.ok(warnings.every(warning => warning.includes("symbol name")));
});

void test("CodeView truncated fixed fields warn and preserve the known symbol kind", async () => {
  const bytes = codeViewDataSymbol(0x1103, [65, 0]).slice(0, 8);
  bytes[0] = bytes.length - 2;
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

  assert.deepEqual(parsed.records, [{ type: 0x1103, data: { kind: "block" } }]);
  assert.match(warnings.join(" "), /symbol fixed fields.*bounds/);
});

void test("CodeView malformed public flags retain reserved bits for visible rendering", async () => {
  const bytes = codeViewDataSymbol(0x110e, [80, 0], 0x10);
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes), 0, bytes.length);

  assert.deepEqual(parsed.records[0]?.data, { kind: "public", location: { segment: 9, offset: 0x1234 },
    publicFlags: 0x10 });
});

void test("CodeView malformed segment and offset fields are bounds-checked", async () => {
  const bytes = codeViewDataSymbol(0x110c, [65, 0]).slice(0, 12);
  bytes[0] = bytes.length - 2;
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

  assert.deepEqual(parsed.records, [{ type: 0x110c, data: { kind: "data" } }]);
  assert.match(warnings.join(" "), /symbol fixed fields.*bounds/);
});
