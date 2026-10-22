import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewSymbolName } from "../../../../../analyzers/pe/debug/legacy-codeview-symbol-names.js";
import { legacyReader, legacySymbol, legacyPascal, legacyU16 } from "../../../../fixtures/pe-legacy-codeview.js";

// Microsoft's packed cvinfo.h layouts include CV_lvar_attr (8 bytes).
// LLVM's SymbolRecordMapping.cpp defines HOTPATCHFUNC and REGREL32_INDIR.
for (const [type, offset] of [[0x101a, 41], [0x101b, 41], [0x1022, 20], [0x1023, 18],
  [0x1024, 20], [0x1026, 22], [0x111e, 20], [0x111f, 18], [0x1120, 20], [0x1122, 22],
  [0x112a, 41], [0x112b, 41], [0x112e, 20], [0x112f, 18], [0x1130, 22],
  [0x1148, 56], [0x1149, 56], [0x114a, 41], [0x114b, 41], [0x1151, 20], [0x1152, 20],
  [0x1153, 14], [0x1154, 14], [0x1155, 39], [0x1156, 39], [0x1160, 12],
  [0x1162, 30], [0x1163, 30], [0x1164, 26], [0x1165, 26], [0x1169, 8], [0x1171, 18]] as const) {
  void test(`CodeView additional symbol ${type} retains its bounded stored name`, async () => {
    assert.equal(await readLegacyCodeViewSymbolName(legacyReader(legacySymbol(type, "stored", offset)), type), "stored");
  });
}

for (const type of [0x101a, 0x101b, 0x112a, 0x112b]) {
  void test(`CodeView managed procedure ${type} accepts an absent optional name`, async () => {
    assert.equal(await readLegacyCodeViewSymbolName(legacyReader(new Uint8Array(41)), type), null);
    await assert.rejects(readLegacyCodeViewSymbolName(legacyReader(new Uint8Array(40)), type), /bounds/);
  });
}

for (const [type, prefix] of [[0x1025, 17], [0x1027, 18], [0x1121, 17], [0x1123, 18], [0x1131, 18]] as const) {
  void test(`CodeView attributed multi-register symbol ${type} skips the complete register array`, async () => {
    const bytes = legacySymbol(type, "stored", prefix + (prefix === 17 ? 3 : 6));
    bytes[16] = 3;

    assert.equal(await readLegacyCodeViewSymbolName(legacyReader(bytes), type), "stored");
    await assert.rejects(readLegacyCodeViewSymbolName(legacyReader(bytes.slice(0, prefix)), type), /bounds|terminated/);
  });
}

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
