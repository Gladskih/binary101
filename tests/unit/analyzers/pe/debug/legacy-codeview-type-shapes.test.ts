import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewTypeShape } from "../../../../../analyzers/pe/debug/legacy-codeview-type-shapes.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewTextRecord } from "../../../../fixtures/pe-codeview-type-strings.js";
import { codeViewArguments, codeViewMemberFunction, codeViewProcedure } from "../../../../fixtures/pe-codeview-callables.js";

for (const leaf of [8, 0x1008]) {
  void test(`CodeView procedure ${leaf} retains its return type, attributes and argument-list reference`, async () => {
    const warnings: string[] = [];
    assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewProcedure(leaf), warnings), leaf), {
      kind: "procedure", returnType: 0x74, callingConvention: 7, attributes: 1,
      parameterCount: 2, argumentList: 0x1000
    });
    assert.deepEqual(warnings, []);
  });
}

for (const leaf of [9, 0x1009]) {
  void test(`CodeView member function ${leaf} retains its class, this pointer and signed adjustment`, async () => {
    assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewMemberFunction(leaf)), leaf), {
      kind: "memberFunction", returnType: 0x74, classType: 0x1002, thisType: 0x1003,
      callingConvention: 11, attributes: 2, parameterCount: 2, argumentList: 0x1000, thisAdjustment: -8
    });
  });
}

for (const leaf of [0x201, 0x1201]) {
  void test(`CodeView argument list ${leaf} respects index width and permits a variadic marker`, async () => {
    assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewArguments([0x74, 0], leaf)), leaf),
      { kind: "arguments", types: [0x74, 0] });
    assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewArguments([], leaf)), leaf),
      { kind: "arguments", types: [] });
    await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewArguments([0x74], leaf).slice(0, -1)), leaf), /bounds/);
  });
}

void test("CodeView unknown type shapes remain explicitly undecoded", async () => {
  assert.equal(await readCodeViewTypeShape(legacyReader([]), 0x7777), undefined);
});

void test("CodeView truncated procedure and member function bodies are bounded", async () => {
  await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewProcedure().slice(0, -1)), 0x1008), /bounds/);
  await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewMemberFunction().slice(0, -1)), 0x1009), /bounds/);
});

void test("CodeView modifiers, pointers and aliases preserve underlying type references", async () => {
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(1, 4,
    [...legacyU16(3), ...legacyU16(0x74)])), 1), { kind: "modifier", typeIndex: 0x74, attributes: 3 });
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1001, 4,
    [...legacyU32(0x41), ...legacyU16(4)])), 0x1001), { kind: "modifier", typeIndex: 0x41, attributes: 4 });
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(2, 4,
    [...legacyU16(0x20), ...legacyU16(0x1001)])), 2), { kind: "pointer", typeIndex: 0x1001, attributes: 0x20 });
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1002, 4,
    [...legacyU32(0x1001), ...legacyU32(0x40), ...legacyU32(0x1002), ...legacyU16(3)])), 0x1002),
  { kind: "pointer", typeIndex: 0x1001, attributes: 0x40, classType: 0x1002, representation: 3 });
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x150a, 4,
    [...legacyU32(0x74), 0])), 0x150a), { kind: "alias", typeIndex: 0x74 });
});

void test("CodeView function IDs distinguish scope IDs from containing class types", async () => {
  const reader = legacyReader(codeViewTextRecord(0x1601, 4, [...legacyU32(0x1010), ...legacyU32(0x1001)]));
  assert.deepEqual(await readCodeViewTypeShape(reader, 0x1601),
    { kind: "functionId", scopeId: 0x1010, functionType: 0x1001 });
  assert.deepEqual(await readCodeViewTypeShape(reader, 0x1602),
    { kind: "memberFunctionId", classType: 0x1010, functionType: 0x1001 });
});

void test("CodeView unknown function attributes and calling conventions are visible", async () => {
  const warnings: string[] = [];
  const bytes = codeViewProcedure();
  bytes[8] = 0xff;
  bytes[9] = 0x80;
  assert.equal((await readCodeViewTypeShape(legacyReader(bytes, warnings), 0x1008))?.kind, "procedure");
  assert.match(warnings.join(" | "), /calling convention/);
  assert.match(warnings.join(" | "), /attribute bits/);
});

void test("CodeView reserved modifiers and pointer flags are preserved with warnings", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1001, 4,
    [...legacyU32(0x74), ...legacyU16(0x8000)]), warnings), 0x1001),
  { kind: "modifier", typeIndex: 0x74, attributes: 0x8000 });
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1002, 4,
    [...legacyU32(0x41), ...legacyU32(0x8000000c)]), warnings), 0x1002),
  { kind: "pointer", typeIndex: 0x41, attributes: 0x8000000c });
  assert.match(warnings.join(" | "), /modifier.*attribute bits/);
  assert.match(warnings.join(" | "), /pointer.*attribute bits/);
});

void test("CodeView narrow member pointers and old aliases respect their fixed prefixes", async () => {
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(2, 4,
    [...legacyU16(0x6a), ...legacyU16(0x74), ...legacyU16(0x1001), ...legacyU16(7)])), 2),
  { kind: "pointer", typeIndex: 0x74, attributes: 0x6a, classType: 0x1001, representation: 7 });
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1010, 4,
    legacyU32(0x75))), 0x1010), { kind: "alias", typeIndex: 0x75 });
  await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1201, 4,
    legacyU32(0xffffffff))), 0x1201), /bounds/);
});

void test("CodeView the reserved calling-convention slot is not silently accepted", async () => {
  const warnings: string[] = [];
  const bytes = codeViewProcedure();
  bytes[8] = 6;
  await readCodeViewTypeShape(legacyReader(bytes, warnings), 0x1008);
  assert.match(warnings.join(" | "), /unknown calling convention 6/);
});

void test("CodeView vectorcall and combinations of valid function and modifier attributes stay valid", async () => {
  const warnings: string[] = [];
  const bytes = codeViewProcedure();
  bytes[8] = 24; // CV_CALL_NEAR_VECTOR, last defined value in Microsoft cvconst.h.
  bytes[9] = 7; // All three CV_funcattr_t bits.
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(bytes, warnings), 0x1008), {
    kind: "procedure", returnType: 0x74, callingConvention: 24, attributes: 7,
    parameterCount: 2, argumentList: 0x1000
  });
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1001, 4,
    [...legacyU32(0x12345678), ...legacyU16(7)]), warnings), 0x1001),
  { kind: "modifier", typeIndex: 0x12345678, attributes: 7 });
  assert.deepEqual(warnings, []);
});

void test("CodeView pointer flags use distinct 16-bit and 32-bit reserved masks", async () => {
  const warnings: string[] = [];
  await readCodeViewTypeShape(legacyReader(codeViewTextRecord(2, 4,
    [...legacyU16(0x100a), ...legacyU16(0x74)]), warnings), 2);
  assert.deepEqual(warnings, ["CodeView pointer has unknown attribute bits."]);
  warnings.length = 0;
  await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1002, 4,
    [...legacyU32(0x74), ...legacyU32(0x100c)]), warnings), 0x1002);
  assert.deepEqual(warnings, []);
});
