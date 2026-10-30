import assert from "node:assert/strict";
import { test } from "node:test";
import { readTd32TypeBody } from "../../../../../analyzers/pe/debug/td32-type-body.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

// map2dbg 70cd89ff Program.cs TypModifier/Pointer/Struct/Procedure/MFunction/ArgList.Read.
const payloads = () => ({
  modifier: [...legacyU16(5), ...legacyU32(0x1002)],
  pointer: [...legacyU16(0x44a), ...legacyU32(0x1003), ...legacyU16(2), ...legacyU32(0x1004)],
  structure: [...legacyU16(3), ...legacyU32(0x1005), ...legacyU16(0x81),
    ...legacyU32(0x1006), ...legacyU32(0x1007), ...legacyU32(0x1008),
    ...legacyU32(2), ...legacyU16(0x8004), ...legacyU32(0x80000000)],
  enumeration: [...legacyU16(4), ...legacyU32(0x74), ...legacyU32(0x1005),
    ...legacyU32(0x1006), ...legacyU32(2)],
  procedure: [...legacyU32(0x74), 0x47, 1, ...legacyU16(2), ...legacyU32(0x1005)],
  member: [...legacyU32(0x74), ...legacyU32(0x1002), ...legacyU32(0x1003),
    11, 0, ...legacyU16(1), ...legacyU32(0x1004), ...legacyU32(-8)],
  arguments: [...legacyU16(2), ...legacyU32(0x74), ...legacyU32(0x1002)],
  bitfield: [7, 3, ...legacyU32(0x75)]
});

void test("TD32 modifier and member pointer retain stored qualifier bits and type relations", async () => {
  assert.deepEqual(await readTd32TypeBody(legacyReader(payloads().modifier), 1),
    { attributes: 5, targetType: 0x1002 });
  assert.deepEqual(await readTd32TypeBody(legacyReader(payloads().pointer), 2),
    { attributes: 0x44a, targetType: 0x1003, memberAttributes: 2, classType: 0x1004 });
  assert.deepEqual(await readTd32TypeBody(legacyReader(payloads().modifier), 2),
    { attributes: 5, targetType: 0x1002 });
  assert.deepEqual(await readTd32TypeBody(legacyReader([
    ...legacyU16(0x66a), ...payloads().pointer.slice(2)
  ]), 2), { attributes: 0x66a, targetType: 0x1003, memberAttributes: 2, classType: 0x1004 });
});

void test("TD32 class and enum preserve relation slots whose meanings differ across references", async () => {
  const expected = { count: 3, fieldList: 0x1005, attributes: 0x81,
    relation12: 0x1006, relation16: 0x1007, relation20: 0x1008,
    byteSize: { leaf: 0x8004, value: "2147483648" } };
  assert.deepEqual(await readTd32TypeBody(legacyReader(payloads().structure), 4), expected);
  assert.deepEqual(await readTd32TypeBody(legacyReader(payloads().structure), 5), expected);
  assert.deepEqual(await readTd32TypeBody(legacyReader(payloads().enumeration), 7),
    { count: 4, underlyingType: 0x74, fieldList: 0x1005, relation14: 0x1006 });
});

void test("TD32 procedure and member function retain calling conventions and argument relations", async () => {
  assert.deepEqual(await readTd32TypeBody(legacyReader(payloads().procedure), 8),
    { returnType: 0x74, callingConvention: 0x47, functionAttributes: 1,
      parameterCount: 2, argumentList: 0x1005 });
  assert.deepEqual(await readTd32TypeBody(legacyReader(payloads().member), 9),
    { returnType: 0x74, classType: 0x1002, thisType: 0x1003,
      callingConvention: 11, functionAttributes: 0, parameterCount: 1,
      argumentList: 0x1004, thisAdjustment: -8 });
});

void test("TD32 argument lists and bit fields use Borland count and field order", async () => {
  assert.deepEqual(await readTd32TypeBody(legacyReader(payloads().arguments), 0x201),
    { argumentTypes: [0x74, 0x1002] });
  assert.deepEqual(await readTd32TypeBody(legacyReader(legacyU16(0)), 0x201), { argumentTypes: [] });
  assert.deepEqual(await readTd32TypeBody(legacyReader(payloads().bitfield), 0x206),
    { bitLength: 7, bitPosition: 3, underlyingType: 0x75 });
});

const rejectTruncations = async (type: number, payload: number[], minimum: number): Promise<void> => {
  for (let size = 0; size < minimum; size++) {
    const warnings: string[] = [];
    assert.equal(await readTd32TypeBody(legacyReader(payload.slice(0, size), warnings), type), undefined);
    assert.match(warnings.join(" | "), /TD32 type body.*bounds/);
  }
};
void test("TD32 type body truncations warn without rejecting the record framing", async () => {
  await rejectTruncations(1, payloads().modifier, 6);
  await rejectTruncations(2, payloads().pointer, 12);
  await rejectTruncations(4, payloads().structure, 20);
  await rejectTruncations(7, payloads().enumeration, 14);
  await rejectTruncations(8, payloads().procedure, 12);
  await rejectTruncations(9, payloads().member, 24);
  await rejectTruncations(0x201, payloads().arguments, 10);
  await rejectTruncations(0x206, payloads().bitfield, 6);
});

void test("TD32 class size failures retain validated relations and unknown numeric encodings", async () => {
  const warnings: string[] = [];
  const truncated = await readTd32TypeBody(legacyReader(payloads().structure.slice(0, 24), warnings), 4);
  assert.equal(truncated?.fieldList, 0x1005);
  assert.equal(truncated?.byteSize, undefined);
  assert.match(warnings.join(" | "), /TD32 type size.*bounds/);
  const floating = [...payloads().structure.slice(0, 24), ...legacyU16(0x8005), ...legacyU32(0)];
  assert.deepEqual((await readTd32TypeBody(legacyReader(floating), 4))?.byteSize, { leaf: 0x8005 });
});

void test("TD32 does not guess array, union or unrecognized type body layouts", async () => {
  assert.equal(await readTd32TypeBody(legacyReader([]), 3), undefined);
  assert.equal(await readTd32TypeBody(legacyReader([]), 6), undefined);
  assert.equal(await readTd32TypeBody(legacyReader([]), 0xffff), undefined);
});
