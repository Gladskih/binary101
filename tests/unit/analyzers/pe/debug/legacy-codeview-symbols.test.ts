import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewSymbols, readLegacyCodeViewGlobalSymbols,
  readLegacyCodeViewModuleSymbols } from "../../../../../analyzers/pe/debug/legacy-codeview-symbols.js";
import { legacyReader, legacySymbol, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("CodeView symbol scan retains named symbols and unnamed scope records", async () => {
  const records = [...legacySymbol(), 2, 0, 6, 0];
  const global = await readLegacyCodeViewGlobalSymbols(legacyReader([
    0, 0, 0, 0, ...legacyU32(records.length), ...legacyU32(0), ...legacyU32(0), ...records]));
  const local = await readLegacyCodeViewModuleSymbols(legacyReader([...legacyU32(1), ...records]));

  assert.deepEqual(global, { kind: "symbols", records: [{ type: 0x203, name: "public_name" }, { type: 6 }] });
  assert.deepEqual(local, global);
  await assert.rejects(readLegacyCodeViewModuleSymbols(legacyReader([...legacyU32(9)])), /signature/);
});

void test("CodeView damaged name does not discard later symbols", async () => {
  const bytes = [2, 0, 3, 2, ...legacySymbol()];
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

  assert.deepEqual(parsed.records, [{ type: 0x203 }, { type: 0x203, name: "public_name" }]);
  assert.match(warnings.join(" | "), /symbol 515:.*bounds/);
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
