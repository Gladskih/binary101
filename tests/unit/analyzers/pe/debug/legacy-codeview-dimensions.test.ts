import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewTypeShape } from "../../../../../analyzers/pe/debug/legacy-codeview-type-shapes.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewTextRecord } from "../../../../fixtures/pe-codeview-type-strings.js";
import { codeViewConstantDimensions, codeViewVariableDimensions } from "../../../../fixtures/pe-codeview-dimensions.js";
import { readCodeViewDimensions } from "../../../../../analyzers/pe/debug/legacy-codeview-dimensions.js";
import { createPeWithCodeViewDimensions } from "../../../../fixtures/pe-codeview-dimensions.js";
import { parsePeHeaders } from "../../../../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";
import { buildCodeViewArrayBounds } from "../../../../../renderers/pe/codeview-array-bounds.js";

for (const [leaf, references, dimensionsType] of [[0x11, [...legacyU16(0x74), ...legacyU16(0x1000)], 0x1000],
  [0x100c, [...legacyU32(0x74), ...legacyU32(0x12345678)], 0x12345678],
  [0x1508, [...legacyU32(0x74), ...legacyU32(0x12345678)], 0x12345678]] as const) {
  void test(`CodeView dimensioned array ${leaf} keeps its underlying type and dimension reference`, async () => {
    assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(leaf, 4, references)), leaf),
      { kind: "dimensionedArray", underlyingType: 0x74, dimensionsType });
    await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewTextRecord(leaf, 4,
      references.slice(0, -1))), leaf), /bounds/);
  });
}

void test("CodeView dimension readers leave other leaves untouched", async () => {
  assert.equal(await readCodeViewDimensions(legacyReader([]), 0xffff), undefined);
});

for (const leaf of [0x20b, 0x120a]) {
  void test(`CodeView truncated variable bounds ${leaf} retain complete references`, async () => {
    const warnings: string[] = [];
    assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewVariableDimensions(leaf, 0x74, 2,
      [0x1000, 0x1001, 0x1002]), warnings), leaf), { kind: "variableDimensions", indexType: 0x74,
      rank: 2, boundKind: "lowerUpper", bounds: [0x1000, 0x1001, 0x1002] });
    assert.deepEqual(warnings, ["CodeView variable array dimensions have truncated bound references."]);
    await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewTextRecord(leaf, 4, [0])), leaf), /bounds/);
  });
}

void test("CodeView DWORD ranks cannot allocate more references than fit in the record", async () => {
  const warnings: string[] = [];
  const shape = await readCodeViewTypeShape(legacyReader(codeViewVariableDimensions(0x120a, 0x74,
    0xffffffff, [0x87654321]), warnings), 0x120a);
  assert.deepEqual(shape, { kind: "variableDimensions", indexType: 0x74, rank: 0xffffffff,
    boundKind: "lowerUpper", bounds: [0x87654321] });
  assert.match(warnings.join(" | "), /truncated bound references/);
});

void test("CodeView empty dimensions remain empty without borrowing record padding", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewVariableDimensions(0x1209, 0x74,
    0, []), warnings), 0x1209), { kind: "variableDimensions", indexType: 0x74,
    rank: 0, boundKind: "upper", bounds: [] });
  assert.deepEqual(warnings, []);
});

void test("PE integration retains exact constant and named variable bounds", async () => {
  const file = createPeWithCodeViewDimensions();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const info = debug.entries[0]?.legacyCodeView;
  assert.ok(info);
  assert.equal(debug.warning, null);
  assert.deepEqual(buildCodeViewArrayBounds(info)[0]?.rows, [
    ["1", "1", "<Grid>&amp; (rank: 2)", "int32", "1", "-1", "3"],
    ["1", "1", "<Grid>&amp; (rank: 2)", "int32", "2", "2", "5"],
    ["1", "1", "Dynamic (rank: 1)", "int32", "1", "(unspecified)", "<limit>&amp;"],
    ["1", "1", "dimensions #4101 (rank: 1)", "uint64", "1", "(language default)", "18446744073709551615"]
  ]);
});

for (const [leaf, boundKind] of [[0x208, "upper"], [0x209, "lowerUpper"],
  [0x1207, "upper"], [0x1208, "lowerUpper"]] as const) {
  void test(`CodeView constant dimensions ${leaf} retain bounded bytes until the index width is resolved`, async () => {
    assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewConstantDimensions(leaf, 0x74, 2,
      [1, 0, 0, 0])), leaf), { kind: "constantDimensions", indexType: 0x74, rank: 2,
      boundKind, bounds: { kind: "encoded", bytes: Uint8Array.of(1, 0, 0, 0) } });
    await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewTextRecord(leaf, 4, [0])), leaf), /bounds/);
  });
}

for (const [leaf, boundKind, indices] of [[0x20a, "upper", [0x1000]],
  [0x20b, "lowerUpper", [0x1000, 0x1001]], [0x1209, "upper", [0x12345678]],
  [0x120a, "lowerUpper", [0x12345678, 0x87654321]]] as const) {
  void test(`CodeView variable dimensions ${leaf} use the stored type-index width`, async () => {
    const warnings: string[] = [];
    assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewVariableDimensions(leaf, 0x74, 1,
      indices), warnings), leaf), { kind: "variableDimensions", indexType: 0x74, rank: 1,
      boundKind, bounds: indices });
    assert.deepEqual(warnings, []);
  });
}
