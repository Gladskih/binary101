import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewModuleTypes, type LegacyCodeViewTypeRecord } from "../../../../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { resolveCodeViewConstantBounds } from "../../../../../analyzers/pe/debug/legacy-codeview-constant-bounds.js";
import { legacyReader, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewConstantDimensions, codeViewFixedInteger } from "../../../../fixtures/pe-codeview-dimensions.js";

const encodedDimensions = (indexType: number, bytes: readonly number[]): LegacyCodeViewTypeRecord => ({
  type: 0x1208, index: 0x1000, shape: { kind: "constantDimensions", indexType, rank: 1,
    boundKind: "lowerUpper", bounds: { kind: "encoded", bytes: Uint8Array.from(bytes) } }
});

const signedCases = [0x10, 0x11, 0x12, 0x13, 0x14, 0x68, 0x72, 0x74, 0x76, 0x78]
  .map((type, index) => ({ type, width: 2 ** (index % 5),
    low: -(1n << BigInt(8 * 2 ** (index % 5) - 1)), high: (1n << BigInt(8 * 2 ** (index % 5) - 1)) - 1n }));
const unsignedCases = [0x20, 0x21, 0x22, 0x23, 0x24, 0x69, 0x73, 0x75, 0x77, 0x79]
  .map((type, index) => ({ type, width: 2 ** (index % 5), low: 0n,
    high: (1n << BigInt(8 * 2 ** (index % 5))) - 1n }));

for (const { type, width, low, high } of [...signedCases, ...unsignedCases]) {
  void test(`CodeView fixed integer bound type ${type} preserves its exact signedness and ${width}-byte width`, () => {
    const warnings: string[] = [];
    const decoded = resolveCodeViewConstantBounds([encodedDimensions(type,
      [...codeViewFixedInteger(low, width), ...codeViewFixedInteger(high, width)])], message => warnings.push(message));
    assert.deepEqual(decoded[0]?.shape, { kind: "constantDimensions", indexType: type, rank: 1,
      boundKind: "lowerUpper", bounds: { kind: "integers", values: [String(low), String(high)] } });
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView constant dimensions follow their integer index width, not numeric-leaf tags", async () => {
  const warnings: string[] = [];
  const types = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewConstantDimensions(0x209, 0x74, 2,
      [-1n, 3n, 2n, 5n].flatMap(value => codeViewFixedInteger(value, 4)))], warnings));
  assert.deepEqual(types.records[0]?.shape, { kind: "constantDimensions", indexType: 0x74, rank: 2,
    boundKind: "lowerUpper", bounds: { kind: "integers", values: ["-1", "3", "2", "5"] } });
  assert.deepEqual(warnings, []);
});

void test("CodeView forward aliases, modifiers and enum index types resolve before bound decoding", () => {
  const warnings: string[] = [];
  const decoded = resolveCodeViewConstantBounds([
    encodedDimensions(0x1001, [...codeViewFixedInteger(-7n, 8), ...codeViewFixedInteger(9n, 8)]),
    { type: 0x150a, index: 0x1001, shape: { kind: "alias", typeIndex: 0x1002 } },
    { type: 0x1001, index: 0x1002, shape: { kind: "modifier", typeIndex: 0x1003, attributes: 1 } },
    { type: 0x1518, index: 0x1003, shape: { kind: "extendedModifier", typeIndex: 0x1004, modifiers: [1] } },
    { type: 0x1507, index: 0x1004, shape: { kind: "aggregate", underlyingType: 0x76,
      properties: 0, fieldList: 0 } }
  ], message => warnings.push(message));
  assert.deepEqual(decoded[0]?.shape, { kind: "constantDimensions", indexType: 0x1001, rank: 1,
    boundKind: "lowerUpper", bounds: { kind: "integers", values: ["-7", "9"] } });
  assert.deepEqual(warnings, []);
});

void test("CodeView bound index aliases at the first nonprimitive index still resolve", () => {
  const record = encodedDimensions(0x1000, [...legacyU32(2), ...legacyU32(5)]);
  record.index = 0x1001;
  assert.deepEqual(resolveCodeViewConstantBounds([
    { type: 0x150a, index: 0x1000, shape: { kind: "alias", typeIndex: 0x74 } }, record
  ], () => assert.fail("valid bound alias must not warn"))[1]?.shape,
  { kind: "constantDimensions", indexType: 0x1000, rank: 1, boundKind: "lowerUpper",
    bounds: { kind: "integers", values: ["2", "5"] } });
});

void test("CodeView basic arrays are not treated as integer bound aliases", () => {
  const warnings: string[] = [];
  const record = encodedDimensions(0x1001, [1]);
  const decoded = resolveCodeViewConstantBounds([record,
    { type: 0x000d, index: 0x1001, shape: { kind: "basicArray", typeIndex: 0x74 } }
  ], message => warnings.push(message));
  assert.deepEqual(decoded[0]?.shape, record.shape);
  assert.match(warnings.join(" | "), /unresolved or noninteger index type #4097/);
});

for (const records of [
  [encodedDimensions(0x1001, [0]), { type: 0x150a, index: 0x1001, shape: { kind: "alias", typeIndex: 0x1001 } }],
  [encodedDimensions(0x1001, [0])],
  [encodedDimensions(0x1001, [0]), { type: 0x1505, index: 0x1001, shape: { kind: "aggregate", properties: 0, fieldList: 0 } }],
  [encodedDimensions(0x40, [0])],
  [encodedDimensions(0x1001, [0]), { type: 0x150a, index: 0x1001, shape: { kind: "alias", typeIndex: 0x74 } },
    { type: 0x150a, index: 0x1001, shape: { kind: "alias", typeIndex: 0x74 } }]
] satisfies LegacyCodeViewTypeRecord[][]) {
  void test(`CodeView unresolved or noninteger bound index ${records[0]?.shape?.kind}/${records.length} retains bytes`, () => {
    const warnings: string[] = [];
    const decoded = resolveCodeViewConstantBounds(records, message => warnings.push(message));
    assert.deepEqual(decoded[0]?.shape, records[0]?.shape);
    assert.match(warnings.join(" | "), /unresolved or noninteger index type/);
  });
}

void test("CodeView truncated constants retain every complete value without inventing an upper bound", () => {
  const warnings: string[] = [];
  const decoded = resolveCodeViewConstantBounds([encodedDimensions(0x74,
    [...codeViewFixedInteger(-1n, 4), 0, 0, 0])], message => warnings.push(message));
  assert.deepEqual(decoded[0]?.shape, { kind: "constantDimensions", indexType: 0x74, rank: 1,
    boundKind: "lowerUpper", bounds: { kind: "integers", values: ["-1"] } });
  assert.deepEqual(warnings, ["CodeView constant array dimensions have truncated bounds."]);
});

void test("CodeView external bounds cannot borrow local aliases and cached shapes remain namespace-specific", () => {
  const warnings: string[] = [];
  const stored = encodedDimensions(0x1001, [...legacyU32(1), ...legacyU32(5)]);
  assert.ok(stored.shape);
  const decoded = resolveCodeViewConstantBounds([
    stored, { ...stored, index: 0x1002 }, { type: stored.type, shape: stored.shape },
    { type: 0x150a, index: 0x1001, shape: { kind: "alias", typeIndex: 0x74 } }
  ], message => warnings.push(message));
  assert.equal(decoded[0]?.shape, decoded[1]?.shape); // One physical OMF record can have several directory slots.
  assert.notEqual(decoded[0]?.shape, decoded[2]?.shape);
  assert.deepEqual(decoded[2]?.shape, stored.shape);
  assert.equal(warnings.length, 1);
});

void test("CodeView resolved bounds and unrelated records need no new decoding", () => {
  const warnings: string[] = [];
  const empty: LegacyCodeViewTypeRecord[] = [];
  assert.equal(resolveCodeViewConstantBounds(empty, message => warnings.push(message)), empty);
  const decoded: NonNullable<LegacyCodeViewTypeRecord["shape"]> = { kind: "constantDimensions", indexType: 0x74,
    rank: 0, boundKind: "upper", bounds: { kind: "integers", values: [] } };
  assert.deepEqual(resolveCodeViewConstantBounds([{ type: 0x1207, shape: decoded }],
    message => warnings.push(message))[0]?.shape, decoded);
  assert.deepEqual(warnings, []);
});
