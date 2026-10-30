import assert from "node:assert/strict";
import { test } from "node:test";
import { readTd32ExtendedTypeBody } from "../../../../../analyzers/pe/debug/td32-extended-type-body.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

// map2dbg TypMList.Read: attr/u32 type/u32 browser, then i32 vtable for mprop 4 or 6.
const method = (attributes: number) => [...legacyU16(attributes), ...legacyU32(0x1002), ...legacyU32(0)];
void test("TD32 method lists retain introducing-virtual offsets and complete prefixes", async () => {
  assert.deepEqual(await readTd32ExtendedTypeBody(legacyReader([
    ...method(3), ...method(0x13), ...legacyU32(-4), ...method(0x1b), ...legacyU32(8)
  ]), 0x207), { methods: [{ attributes: 3, methodType: 0x1002, browserOffset: 0 },
    { attributes: 0x13, methodType: 0x1002, browserOffset: 0, vtableOffset: -4 },
    { attributes: 0x1b, methodType: 0x1002, browserOffset: 0, vtableOffset: 8 }] });
  const warnings: string[] = [];
  assert.deepEqual(await readTd32ExtendedTypeBody(legacyReader([...method(3), 0], warnings), 0x207),
    { methods: [{ attributes: 3, methodType: 0x1002, browserOffset: 0 }] });
  assert.match(warnings.join(" | "), /bounds/);
});
void test("TD32 virtual table descriptors use low nibble first and bound their count", async () => {
  assert.deepEqual(await readTd32ExtendedTypeBody(legacyReader([...legacyU16(3), 0x51, 0x06]), 10),
    { descriptors: [1, 5, 6] });
  assert.deepEqual(await readTd32ExtendedTypeBody(legacyReader(legacyU16(0)), 10), { descriptors: [] });
  await assert.rejects(readTd32ExtendedTypeBody(legacyReader([...legacyU16(0xffff)]), 10), /bounds/);
});
void test("TD32 properties preserve disputed accessor values without choosing their semantics", async () => {
  assert.deepEqual(await readTd32ExtendedTypeBody(legacyReader([
    ...legacyU32(0x74), ...legacyU16(7), ...legacyU32(0x1002), ...legacyU32(0x80000000),
    ...legacyU32(3), ...legacyU32(4)
  ]), 0x35), { underlyingType: 0x74, attributes: 7, indexType: 0x1002,
    propertyIndex: -2147483648, readerValue: 3, writerValue: 4 });
});
void test("TD32 closure prefixes retain unresolved tails instead of emulating the upstream skip bug", async () => {
  assert.deepEqual(await readTd32ExtendedTypeBody(legacyReader([
    ...legacyU32(3), 4, 0, ...legacyU16(2), ...legacyU32(0x1002)
  ]), 0x34), { returnType: 3, callingConvention: 4, functionAttributes: 0,
    closureTail: [...legacyU16(2), ...legacyU32(0x1002)] });
  assert.equal(await readTd32ExtendedTypeBody(legacyReader([]), 0x7777), undefined);
  await assert.rejects(readTd32ExtendedTypeBody(legacyReader([]), 0x34), /bounds/);
  await assert.rejects(readTd32ExtendedTypeBody(legacyReader([]), 0x35), /bounds/);
});

void test("TD32 reserved method properties stop instead of guessing an entry width", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readTd32ExtendedTypeBody(legacyReader([
    ...method(3), ...method(0x1f), ...method(3)
  ], warnings), 0x207), { methods: [{ attributes: 3, methodType: 0x1002, browserOffset: 0 }] });
  assert.match(warnings.join(" | "), /reserved method property/);
});

void test("TD32 extended lists accept empty bodies and warn on unknown vtable and attribute bits", async () => {
  assert.deepEqual(await readTd32ExtendedTypeBody(legacyReader([]),0x204), {fields:[]});
  assert.deepEqual(await readTd32ExtendedTypeBody(legacyReader([]),0x207), {methods:[]});
  const warnings:string[]=[];
  assert.deepEqual(await readTd32ExtendedTypeBody(legacyReader([...legacyU16(1),0x0f],warnings),10),
    {descriptors:[15]});
  assert.deepEqual(await readTd32ExtendedTypeBody(legacyReader(method(0xc003),warnings),0x207),
    {methods:[{attributes:0xc003,methodType:0x1002,browserOffset:0}]});
  assert.match(warnings.join(" | "),/unrecognized descriptors/);
  assert.match(warnings.join(" | "),/reserved bits/);
});
