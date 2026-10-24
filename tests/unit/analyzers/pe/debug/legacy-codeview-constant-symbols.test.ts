import assert from "node:assert/strict";
import { test } from "node:test";
import { LegacyCodeViewReader } from "../../../../../analyzers/pe/debug/legacy-codeview-reader.js";
import { readLegacyCodeViewSymbols } from "../../../../../analyzers/pe/debug/legacy-codeview-symbols.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewInteger } from "../../../../fixtures/pe-codeview-numeric-values.js";

const record = (type: number, index: number[], numeric: number[], name: number[]): number[] => {
  const body = [...legacyU16(type), ...index, ...numeric, ...name];
  return [...legacyU16(body.length), ...body];
};

void test("CodeView constant symbols retain their type reference, exact value, and name", async () => {
  const old = record(3, legacyU16(0x1234), legacyU16(42), [3, 79, 108, 100]);
  const st = record(0x1002, legacyU32(0x12345678),
    [...legacyU16(0x800a), ...legacyU32(0xffffffff), ...legacyU32(0xffffffff)], [1, 83, 0]);
  const sz = record(0x1107, legacyU32(0x87654321),
    [...legacyU16(0x8009), ...legacyU32(0xfffffff9), ...legacyU32(0xffffffff)],
    [0xc3, 0xa9, 0]);
  const warnings: string[] = [];

  const parsed = await readLegacyCodeViewSymbols(legacyReader([...old, ...st, ...sz], warnings), 0,
    old.length + st.length + sz.length);

  assert.deepEqual(parsed.records, [
    { type: 3, name: "Old", constant: { typeIndex: 0x1234, numeric: { byteLength: 2, value: "42" } } },
    { type: 0x1002, name: "S", constant: { typeIndex: 0x12345678,
      numeric: { leaf: 0x800a, byteLength: 10, value: "18446744073709551615" } } },
    { type: 0x1107, name: "é", constant: { typeIndex: 0x87654321,
      numeric: { leaf: 0x8009, byteLength: 10, value: "-7" } } }
  ]);
  assert.deepEqual(warnings, []);
});

void test("CodeView 128-bit constant leaves retain exact signed and unsigned extremes", async () => {
  const signedValue = -(1n << 127n);
  const unsignedValue = (1n << 128n) - 1n;
  const signed = record(0x1107, legacyU32(7), codeViewInteger(0x8017, signedValue, 16), [1, 83, 0]);
  const unsigned = record(0x1107, legacyU32(8), codeViewInteger(0x8018, unsignedValue, 16), [1, 85, 0]);
  const parsed = await readLegacyCodeViewSymbols(legacyReader([...signed, ...unsigned]), 0,
    signed.length + unsigned.length);

  assert.deepEqual(parsed.records.map(item => item.constant?.numeric), [
    { leaf: 0x8017, byteLength: 18, value: signedValue.toString() },
    { leaf: 0x8018, byteLength: 18, value: unsignedValue.toString() }
  ]);
});

void test("CodeView unsupported numeric encodings remain visible without an integer value", async () => {
  const floating = record(0x1107, legacyU32(11), [...legacyU16(0x8007), ...new Array<number>(10).fill(0)],
    [70, 0]);
  const parsed = await readLegacyCodeViewSymbols(legacyReader(floating), 0, floating.length);

  assert.deepEqual(parsed.records[0]?.constant, { typeIndex: 11,
    numeric: { leaf: 0x8007, byteLength: 12 } });
  assert.equal(parsed.records[0]?.name, "F");
});

void test("CodeView malformed numeric leaves preserve their independent type reference", async () => {
  const unknown = record(0x1107, legacyU32(12), legacyU16(0x8fff), [1, 88, 0]);
  const truncated = record(0x1107, legacyU32(13), [...legacyU16(0x8009), 1, 2], []);
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader([...unknown, ...truncated], warnings), 0,
    unknown.length + truncated.length);

  assert.deepEqual(parsed.records.map(item => item.constant), [
    { typeIndex: 12, numeric: { issue: "Error: Unknown CodeView numeric leaf 36863." } },
    { typeIndex: 13, numeric: { issue: "Error: CodeView subsection bounds exceeded." } }
  ]);
  assert.equal(warnings.length, 2);
  assert.ok(warnings.every(warning => warning.includes("constant numeric value")));
});

void test("CodeView constants preserve readable values when type-reference access fails", async () => {
  const bytes = record(0x1107, legacyU32(16), legacyU16(17), [67, 0]);
  const storage = Uint8Array.from(bytes);
  const warnings: string[] = [];
  const reader = new LegacyCodeViewReader(bytes.length, async (offset, size) => {
    if (offset === 4 && size === 4) throw new Error("test range failure");
    return new DataView(storage.buffer, offset, size);
  }, warning => warnings.push(warning));

  const parsed = await readLegacyCodeViewSymbols(reader, 0, bytes.length);

  assert.deepEqual(parsed.records[0], { type: 0x1107, name: "C",
    constant: { numeric: { byteLength: 2, value: "17" } } });
  assert.deepEqual(warnings, ["CodeView constant type reference: Error: test range failure"]);
});

void test("CodeView damaged names keep parsed type and numeric value", async () => {
  const bytes = [...record(0x1107, legacyU32(14), legacyU16(9), [0xff, 0]),
    ...record(3, legacyU16(15), legacyU16(10), [5, 79])];
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

  assert.deepEqual(parsed.records[0], { type: 0x1107,
    constant: { typeIndex: 14, numeric: { byteLength: 2, value: "9" } } });
  assert.deepEqual(parsed.records[1], { type: 3,
    constant: { typeIndex: 15, numeric: { byteLength: 2, value: "10" } } });
  assert.equal(warnings.length, 2);
  assert.ok(warnings.every(warning => warning.includes("constant name")));
});
