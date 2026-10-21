import assert from "node:assert/strict";
import { test } from "node:test";
import { readTd32ModuleSymbols, readTd32GlobalSymbols } from "../../../../../analyzers/pe/debug/td32-symbols.js";
import { td32Symbol } from "../../../../fixtures/pe-td32.js";
import { legacyReader, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

// Independent JCL packed-record offsets include the four-byte symbol record prefix.
for (const [type, offset] of [[2, 10], [3, 8], [4, 10], [9, 8], [0x200, 12],
  [0x201, 16], [0x202, 16], [0x203, 16], [0x204, 40], [0x205, 40], [0x208, 24], [0x209, 12]]) {
  void test(`TD32 symbol ${type} reads its name index at the TD32 offset`, async () => {
    const warnings: string[] = [];

    const parsed = await readTd32ModuleSymbols(legacyReader([...legacyU32(1),
      ...td32Symbol(type, 7, offset)], warnings));

    assert.deepEqual(parsed.records, [{ type, nameIndex: 7 }]);
    assert.deepEqual(warnings, []);
  });
}

void test("TD32 retains compiler names and unknown symbol inventory without guessing", async () => {
  const warnings: string[] = [];

  const parsed = await readTd32ModuleSymbols(legacyReader([...legacyU32(1),
    10, 0, 1, 0, 3, 0, 0, 0, 3, 66, 67, 67, 2, 0, 255, 127], warnings));

  assert.deepEqual(parsed.records, [{ type: 1, compiler: "BCC" }, { type: 0x7fff }]);
  assert.deepEqual(warnings, []);
  assert.deepEqual((await readTd32ModuleSymbols(legacyReader(legacyU32(1)))).records, []);
});

void test("TD32 short symbol names do not discard subsequent bounded records", async () => {
  const warnings: string[] = [];

  const parsed = await readTd32ModuleSymbols(legacyReader([...legacyU32(1), 2, 0, 1, 0,
    ...td32Symbol()], warnings));

  assert.deepEqual(parsed.records, [{ type: 1 }, { type: 0x205, nameIndex: 2 }]);
  assert.match(warnings.join(" | "), /symbol 1.*bounds/);
});

void test("TD32 symbol framing catches partial headers, invalid lengths and missing stream signatures", async () => {
  const warnings: string[] = [];
  await readTd32ModuleSymbols(legacyReader([...legacyU32(1), 0], warnings));
  await readTd32ModuleSymbols(legacyReader([...legacyU32(1), 0, 0, 1, 0], warnings));
  await readTd32ModuleSymbols(legacyReader([...legacyU32(1), 255, 0, 1, 0], warnings));

  assert.match(warnings.join(" | "), /header is truncated/);
  assert.equal(warnings.filter(warning => /length exceeds/.test(warning)).length, 2);
  await assert.rejects(readTd32ModuleSymbols(legacyReader([])), /bounds/);
});

void test("TD32 global symbols start after all eight header DWORDs and exclude hash bytes", async () => {
  const symbol = td32Symbol();
  const warnings: string[] = [];
  const bytes = [...legacyU32(0), ...legacyU32(symbol.length), ...legacyU32(4),
    ...legacyU32(2), ...new Array<number>(16).fill(0), ...symbol, 1, 2, 3, 4, 5, 6];

  const parsed = await readTd32GlobalSymbols(legacyReader(bytes, warnings));

  assert.deepEqual(parsed.records, [{ type: 0x205, nameIndex: 2 }]);
  assert.deepEqual(warnings, []);
  await readTd32GlobalSymbols(legacyReader(bytes.slice(0, -1), warnings));
  assert.match(warnings.join(" | "), /hash streams are truncated/);
  await assert.rejects(readTd32GlobalSymbols(legacyReader([])), /bounds/);
});
