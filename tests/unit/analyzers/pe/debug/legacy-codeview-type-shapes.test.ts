import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewTypeShape } from "../../../../../analyzers/pe/debug/legacy-codeview-type-shapes.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewTextRecord } from "../../../../fixtures/pe-codeview-type-strings.js";
import { codeViewArguments, codeViewMemberFunction, codeViewProcedure } from "../../../../fixtures/pe-codeview-callables.js";

void test("CodeView vtable shapes decode the high nibble first and ignore an unused odd tail nibble", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(10, 4,
    [...legacyU16(3), 0x51, 0x6f]), warnings), 10), { kind: "vtableShape", slots: [5, 1, 6] });
  assert.deepEqual(warnings, []);
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(10, 4,
    [...legacyU16(4), 0x51, 0x6f]), warnings), 10), { kind: "vtableShape", slots: [5, 1, 6, 15] });
  assert.deepEqual(warnings, ["CodeView has unknown vtable slot kinds: 15."]);
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(10, 4, legacyU16(0))), 10),
    { kind: "vtableShape", slots: [] });
  await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewTextRecord(10, 4,
    [...legacyU16(3), 0x51])), 10), /bounds/);
});

void test("CodeView the last published vtable slot kind remains valid", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(10, 4,
    [...legacyU16(1), 0x70]), warnings), 10), { kind: "vtableShape", slots: [7] });
  assert.deepEqual(warnings, []);
});

void test("CodeView vtable shapes honor the entire uint16 descriptor count", async () => {
  const shape = await readCodeViewTypeShape(legacyReader(codeViewTextRecord(10, 4,
    [...legacyU16(0xffff), ...new Array<number>(32768).fill(0x56)])), 10);
  assert.ok(shape?.kind === "vtableShape");
  assert.equal(shape.slots.length, 65535);
  assert.deepEqual(shape.slots.slice(0, 3), [5, 6, 5]);
  assert.equal(shape.slots[65534], 5);
});

for (const [type, bytes] of [[0x207, [...legacyU16(3), ...legacyU16(0x1234)]],
  [0x1206, [...legacyU16(3), ...legacyU16(0), ...legacyU32(0x1234)]]] as const) {
  void test(`CodeView method-list shape ${type} keeps its complete entries`, async () => {
    assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(type, 4, bytes)), type),
      { kind: "methods", methods: [{ attributes: 3, typeIndex: 0x1234 }] });
  });
}

for (const [leaf, bytes, expected] of [
  [0x206, [3, 5, ...legacyU16(0x75)], { kind: "bitfield", typeIndex: 0x75, length: 3, position: 5 }],
  [0x1205, [...legacyU32(0x12345678), 255, 254],
    { kind: "bitfield", typeIndex: 0x12345678, length: 255, position: 254 }]
] as const) {
  void test(`CodeView bitfield ${leaf} retains its base type, width and bit position`, async () => {
    const record = codeViewTextRecord(leaf, 4, bytes);
    assert.deepEqual(await readCodeViewTypeShape(legacyReader(record), leaf), expected);
    await assert.rejects(readCodeViewTypeShape(legacyReader(record.slice(0, -1)), leaf), /bounds/);
  });
}

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

void test("CodeView basic arrays decode 16-bit and 32-bit type indices", async () => {
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x000d, 4,
    legacyU16(0x1234))), 0x000d), { kind: "basicArray", typeIndex: 0x1234 });
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x100b, 4,
    legacyU32(0x12345678))), 0x100b), { kind: "basicArray", typeIndex: 0x12345678 });
  await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x000d, 4,
    legacyU16(0x1234).slice(0, 1))), 0x000d), /bounds/);
});

void test("CodeView labels retain near and far return modes and warn on reserved values", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x000e, 4,
    legacyU16(0)), warnings), 0x000e), { kind: "label", mode: 0 });
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x000e, 4,
    legacyU16(4)), warnings), 0x000e), { kind: "label", mode: 4 });
  assert.deepEqual(warnings, []);
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x000e, 4,
    legacyU16(1)), warnings), 0x000e), { kind: "label", mode: 1 });
  await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x000e, 4,
    legacyU16(0).slice(0, 1))), 0x000e), /bounds/);
  assert.match(warnings.join(" | "), /label has unknown mode 1/);
});

void test("CodeView extended modifiers decode enum values and salvage a truncated list", async () => {
  const warnings: string[] = [];
  const payload = [...legacyU32(0x1000), ...legacyU16(4), ...legacyU16(1), ...legacyU16(0x200),
    ...legacyU16(0x020e), ...legacyU16(0x1234)];
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1518, 4, payload), warnings),
    0x1518), { kind: "extendedModifier", typeIndex: 0x1000,
    modifiers: [1, 0x200, 0x020e, 0x1234] });
  assert.deepEqual(warnings, ["CodeView extended modifier has unknown modifier enum values: 4660."]);
  warnings.length = 0;
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1518, 4,
    [...legacyU32(0x74), ...legacyU16(1), ...legacyU16(0)]), warnings), 0x1518),
  { kind: "extendedModifier", typeIndex: 0x74, modifiers: [0] });
  assert.deepEqual(warnings, ["CodeView extended modifier has invalid modifier enum value 0."]);
  warnings.length = 0;
  const truncated = [...legacyU32(0x74), ...legacyU16(3), ...legacyU16(1), ...legacyU16(2), 0xff];
  assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1518, 4, truncated), warnings),
    0x1518), { kind: "extendedModifier", typeIndex: 0x74, modifiers: [1, 2] });
  assert.match(warnings.join(" | "), /modifier list is truncated/);
  await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1518, 4,
    legacyU32(0x74))), 0x1518), /bounds/);
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
