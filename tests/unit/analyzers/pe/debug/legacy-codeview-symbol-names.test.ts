import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewSymbolName } from "../../../../../analyzers/pe/debug/legacy-codeview-symbol-names.js";
import { legacyReader, legacySymbol, legacyPascal, legacyU16 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("CodeView named symbols use counted ANSI before S_ST_MAX and UTF-8 SZ after it", async () => {
  assert.equal(await readLegacyCodeViewSymbolName(legacyReader(legacySymbol(0x203, "public")), 0x203), "public");
  assert.equal(await readLegacyCodeViewSymbolName(legacyReader(legacySymbol(0x110e, "😀", 14)), 0x110e), "😀");
  assert.equal(await readLegacyCodeViewSymbolName(legacyReader(legacySymbol(0x205, "procedure", 37)), 0x205), "procedure");
  assert.equal(await readLegacyCodeViewSymbolName(legacyReader(legacySymbol(0x100b, "procedure", 39)), 0x100b), "procedure");
  assert.equal(await readLegacyCodeViewSymbolName(legacyReader([2, 0, 6, 0]), 6), null);
});

void test("CodeView constants skip tagged numeric values before reading the name", async () => {
  const counted = [0, 0, 3, 0, 0x74, 0, ...legacyU16(0x8003), 1, 0, 0, 0, ...legacyPascal("answer")];
  const modern = [0, 0, 7, 17, 0x74, 0, 0, 0, 42, 0, 65, 0];

  assert.equal(await readLegacyCodeViewSymbolName(legacyReader(counted), 3), "answer");
  assert.equal(await readLegacyCodeViewSymbolName(legacyReader(modern), 0x1107), "A");
  await assert.rejects(readLegacyCodeViewSymbolName(legacyReader([0, 0, 3, 0]), 3), /bounds/);
});

for (const [type, prefix] of [[0xc, [0, 0, 0, 0, 0, 0, 2, 1, 2]],
  [0x1005, [0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 2]],
  [0x1014, [0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0, 2, 0]]] as const) {
  void test(`CodeView multi-register symbol ${type} skips its declared register array`, async () => {
    assert.equal(await readLegacyCodeViewSymbolName(legacyReader([...prefix, ...legacyPascal("value")]), type), "value");
  });
}
