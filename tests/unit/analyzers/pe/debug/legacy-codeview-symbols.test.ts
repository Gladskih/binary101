import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewSymbols, readLegacyCodeViewGlobalSymbols,
  readLegacyCodeViewModuleSymbols } from "../../../../../analyzers/pe/debug/legacy-codeview-symbols.js";
import { legacyReader, legacySymbol, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewHashIndex, codeViewGlobalSymbols } from "../../../../fixtures/pe-codeview-hash-index.js";
import { codeViewAnnotations } from "../../../../fixtures/pe-codeview-symbol-strings.js";
import { codeViewTextRecord, codeViewUtf8 } from "../../../../fixtures/pe-codeview-type-strings.js";

void test("CodeView symbol scan keeps multi-string prefixes and later records after a damaged field", async () => {
  const warnings: string[] = [];
  const bytes = [...codeViewAnnotations([...codeViewUtf8("kept"), 0xff, 0], 2),
    ...codeViewTextRecord(0x113d, 5, [...codeViewUtf8("cwd"), ...codeViewUtf8("path"), 0]),
    2, 0, 6, 0];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

  assert.deepEqual(parsed.records, [{ type: 0x1019, strings: ["kept"] },
    { type: 0x113d, strings: ["cwd", "path"] }, { type: 6 }]);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /^CodeView symbol string:/);
});

void test("CodeView global symbols retain stored name-bucket and section-index counts", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewGlobalSymbols(legacyReader(codeViewGlobalSymbols(legacySymbol(),
    codeViewHashIndex([0, 2, 1]), codeViewHashIndex([1, 0, 2])), warnings));

  assert.deepEqual(parsed, { kind: "symbols", records: [{ type: 0x203, name: "public_name",
    data: { kind: "public", typeIndex: 0, location: { segment: 0, offset: 0 } } }],
    nameIndex: { algorithm: 10, counts: [0, 2, 1] }, addressIndex: { algorithm: 12, counts: [1, 0, 2] } });
  assert.deepEqual(warnings, []);
});

for (const length of [0, 1, 4]) {
  void test(`CodeView symbol bounds reject length ${length} before scanning following index bytes`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewSymbols(legacyReader([0, 0, 0, 0,
      ...legacyU16(length), 6, 0, 2, 0, 6, 0], warnings), 4, 8);

    assert.deepEqual(parsed.records, []);
    assert.deepEqual(warnings, ["Error: Invalid CodeView symbol record length."]);
  });
}

void test("CodeView address index counts cannot use declared chain bytes missing from the file", async () => {
  const warnings: string[] = [];
  const bytes = codeViewGlobalSymbols(legacySymbol(), codeViewHashIndex([1]), codeViewHashIndex([1]));
  const parsed = await readLegacyCodeViewGlobalSymbols(legacyReader(bytes.slice(0, -1), warnings));

  assert.deepEqual(parsed.addressIndex, { algorithm: 12, counts: [1] });
  assert.deepEqual(warnings, ["CodeView symbol or address hash tables are truncated.",
    "CodeView index group 1 has a misaligned or truncated chain."]);
});

void test("CodeView address indexes cannot borrow trailing data outside their declared extent", async () => {
  const warnings: string[] = [];
  const bytes = codeViewGlobalSymbols(legacySymbol(), [], codeViewHashIndex([1]), 0);
  bytes.splice(12, 4, ...legacyU32(12)); // Only header + parallel arrays belong to the address index.
  const parsed = await readLegacyCodeViewGlobalSymbols(legacyReader(bytes, warnings));

  assert.deepEqual(parsed.addressIndex, { algorithm: 12, counts: [1] });
  assert.deepEqual(warnings, ["CodeView index group 1 has a misaligned or truncated chain."]);
});

void test("CodeView damaged name index cannot consume a valid following address index", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewGlobalSymbols(legacyReader(codeViewGlobalSymbols(legacySymbol(),
    [1, 0], codeViewHashIndex([1])), warnings));

  assert.deepEqual(parsed.nameIndex, { algorithm: 10 });
  assert.deepEqual(parsed.addressIndex, { algorithm: 12, counts: [1] });
  assert.equal(parsed.records[0]?.name, "public_name");
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /^CodeView index counts:/);
});

void test("CodeView truncated name data never shifts the declared address-index origin", async () => {
  const warnings: string[] = [];
  const bytes = codeViewGlobalSymbols(legacySymbol(), codeViewHashIndex([1]), codeViewHashIndex([2]));
  const parsed = await readLegacyCodeViewGlobalSymbols(legacyReader(bytes.slice(0, -30), warnings));

  assert.deepEqual(parsed.nameIndex, { algorithm: 10, counts: [1] });
  assert.deepEqual(parsed.addressIndex, { algorithm: 12 });
  assert.equal(parsed.records.length, 1);
  assert.ok(warnings.includes("CodeView symbol or address hash tables are truncated."));
  assert.ok(warnings.some(warning => warning.includes("truncated chain")));
  assert.ok(warnings.some(warning => warning.includes("index counts:")));
});

void test("CodeView unknown index algorithms remain visible without suppressing symbol names", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewGlobalSymbols(legacyReader(codeViewGlobalSymbols(legacySymbol(),
    [], [], 1, 7), warnings));

  assert.deepEqual(parsed.nameIndex, { algorithm: 1 });
  assert.deepEqual(parsed.addressIndex, { algorithm: 7 });
  assert.equal(parsed.records[0]?.name, "public_name");
  assert.deepEqual(warnings, ["CodeView index algorithm 1 is not decoded.",
    "CodeView index algorithm 7 is not decoded."]);
});

void test("CodeView symbol scan retains named symbols and unnamed scope records", async () => {
  const records = [...legacySymbol(), 2, 0, 6, 0];
  const global = await readLegacyCodeViewGlobalSymbols(legacyReader([
    0, 0, 0, 0, ...legacyU32(records.length), ...legacyU32(0), ...legacyU32(0), ...records]));
  const local = await readLegacyCodeViewModuleSymbols(legacyReader([...legacyU32(1), ...records]));

  assert.deepEqual(global, { kind: "symbols", records: [{ type: 0x203, name: "public_name",
    data: { kind: "public", typeIndex: 0, location: { segment: 0, offset: 0 } } }, { type: 6 }] });
  assert.deepEqual(local, global);
  await assert.rejects(readLegacyCodeViewModuleSymbols(legacyReader([...legacyU32(9)])), /signature/);
});

void test("CodeView damaged name does not discard later symbols", async () => {
  const bytes = [2, 0, 3, 2, ...legacySymbol()];
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

  assert.deepEqual(parsed.records, [{ type: 0x203, data: { kind: "public" } }, { type: 0x203, name: "public_name",
    data: { kind: "public", typeIndex: 0, location: { segment: 0, offset: 0 } } }]);
  assert.match(warnings.join(" | "), /symbol fixed fields:.*bounds/);
});

for (const suffix of [[1, 0, 0], [255, 255], [1]]) {
  void test(`CodeView symbol scan stops safely at a damaged record ${suffix}`, async () => {
    const bytes = [...legacySymbol(), ...suffix];
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

    assert.equal(parsed.records.length, 1);
    assert.match(warnings.join(" | "), /length|bounds/);
  });
}

void test("CodeView hash indexes are bounded separately from the actual symbol array", async () => {
  const records = legacySymbol();
  const warnings: string[] = [];
  const bytes = [0, 0, 0, 0, ...legacyU32(records.length), ...legacyU32(100), ...legacyU32(0), ...records];
  const parsed = await readLegacyCodeViewGlobalSymbols(legacyReader(bytes, warnings));

  assert.equal(parsed.records.length, 1);
  assert.match(warnings.join(" | "), /hash tables are truncated/);
  await assert.rejects(readLegacyCodeViewGlobalSymbols(legacyReader(bytes.slice(0, 16))), /symbol array/);
});
