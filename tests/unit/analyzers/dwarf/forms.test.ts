"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { readDwarfForm } from "../../../../analyzers/dwarf/forms.js";
import type { DwarfFormValue, DwarfUnitContext } from "../../../../analyzers/dwarf/types.js";
import {
  TEST_DWARF,
  TEST_INTEGER,
  concatenateBytes,
  encodeBlock1,
  encodeBlock2,
  encodeBlock4,
  encodeCString,
  encodeRepeatedByte,
  encodeSequence,
  encodeSleb,
  encodeUint8,
  encodeUint16,
  encodeUint32,
  encodeUint64,
  encodeUleb,
  encodeVariableBlock
} from "../../../fixtures/dwarf-fixture-encoding.js";
import { MockFile } from "../../../helpers/mock-file.js";

// The test form registry is an independent oracle from DWARF 5 Table 7.5:
// https://dwarfstd.org/doc/DWARF5.pdf

const context: DwarfUnitContext = {
  version: TEST_DWARF.version.four,
  format: TEST_DWARF.format.dwarf32,
  addressSize: TEST_DWARF.addressSize.x64,
  stringOffsetsBase: null
};

const readForm = async (
  form: number,
  bytes: number[],
  implicitConstant: bigint | null = null,
  unitContext: DwarfUnitContext = context
): Promise<{ value: DwarfFormValue | null; issues: string[] }> => {
  const issues: string[] = [];
  const file = new MockFile(Uint8Array.from(bytes));
  const cursor = new DwarfCursor(
    file,
    { name: ".debug_info", offset: 0, size: bytes.length, compressed: false },
    0,
    bytes.length,
    true,
    issues
  );
  const value = await readDwarfForm(
    cursor,
    { name: TEST_DWARF.attribute.name, form, implicitConstant },
    unitContext
  );
  return { value, issues };
};

void test("readDwarfForm reads fixed-width address, data, reference, and offset forms", async () => {
  assert.deepEqual((await readForm(
    TEST_DWARF.form.address,
    encodeUint64(TEST_INTEGER.ascendingUint64)
  )).value,
    { kind: "unsigned", value: TEST_INTEGER.ascendingUint64 });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.data2,
    encodeUint16(TEST_INTEGER.uint16)
  )).value, { kind: "unsigned", value: BigInt(TEST_INTEGER.uint16) });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.data4,
    encodeUint32(TEST_INTEGER.uint32)
  )).value, { kind: "unsigned", value: BigInt(TEST_INTEGER.uint32) });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.data8,
    encodeUint64(TEST_INTEGER.uint8)
  )).value, { kind: "unsigned", value: BigInt(TEST_INTEGER.uint8) });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.reference1,
    encodeUint8(TEST_INTEGER.uint8)
  )).value, { kind: "unsigned", value: BigInt(TEST_INTEGER.uint8) });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.sectionOffset,
    encodeUint32(TEST_INTEGER.uint8)
  )).value, { kind: "unsigned", value: BigInt(TEST_INTEGER.uint8) });
});

void test("readDwarfForm reads inline, offset, variable, flag, and implicit values", async () => {
  assert.deepEqual((await readForm(TEST_DWARF.form.string, encodeCString("hi"))).value,
    { kind: "string", value: "hi" });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.stringPointer,
    encodeUint32(TEST_INTEGER.uint8)
  )).value, {
    kind: "string-offset",
    value: BigInt(TEST_INTEGER.uint8),
    sectionName: ".debug_str"
  });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.lineStringPointer,
    encodeUint32(TEST_INTEGER.uint8)
  )).value, {
    kind: "string-offset",
    value: BigInt(TEST_INTEGER.uint8),
    sectionName: ".debug_line_str"
  });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.signedData,
    encodeSleb(TEST_INTEGER.negativeSleb)
  )).value, { kind: "signed", value: TEST_INTEGER.negativeSleb });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.unsignedData,
    encodeUleb(TEST_INTEGER.multibyteUleb)
  )).value, { kind: "unsigned", value: TEST_INTEGER.multibyteUleb });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.flag,
    encodeUint8(TEST_DWARF.flag.present)
  )).value,
    { kind: "flag", value: true });
  assert.deepEqual((await readForm(TEST_DWARF.form.flagPresent, [])).value,
    { kind: "flag", value: true });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.implicitConstant,
    [],
    TEST_INTEGER.implicitConstant
  )).value, { kind: "signed", value: TEST_INTEGER.implicitConstant });
});

void test("readDwarfForm skips all standard block encodings", async () => {
  const payload = encodeSequence(Uint16Array.BYTES_PER_ELEMENT);

  assert.deepEqual((await readForm(TEST_DWARF.form.block2, encodeBlock2(payload))).value,
    { kind: "empty" });
  assert.deepEqual((await readForm(TEST_DWARF.form.block4, encodeBlock4(payload))).value,
    { kind: "empty" });
  assert.deepEqual((await readForm(TEST_DWARF.form.block, encodeVariableBlock(payload))).value,
    { kind: "empty" });
  assert.deepEqual((await readForm(TEST_DWARF.form.block1, encodeBlock1(payload))).value,
    { kind: "empty" });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.expressionLocation,
    encodeVariableBlock(payload)
  )).value, { kind: "empty" });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.data16,
    encodeRepeatedByte(TEST_DWARF.encoding.paddingByte, TEST_DWARF.encodedSize.data16)
  )).value,
    { kind: "empty" });
});

void test("readDwarfForm reads standard and GNU indexed forms", async () => {
  assert.deepEqual((await readForm(
    TEST_DWARF.form.stringIndex,
    encodeUleb(TEST_INTEGER.uint8)
  )).value, { kind: "string-index", value: BigInt(TEST_INTEGER.uint8) });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.stringIndex1,
    encodeUint8(TEST_INTEGER.uint8)
  )).value, { kind: "string-index", value: BigInt(TEST_INTEGER.uint8) });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.stringIndex4,
    encodeUint32(TEST_INTEGER.uint8)
  )).value, { kind: "string-index", value: BigInt(TEST_INTEGER.uint8) });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.addressIndex1,
    encodeUint8(TEST_INTEGER.uint8)
  )).value, { kind: "unsigned", value: BigInt(TEST_INTEGER.uint8) });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.addressIndex4,
    encodeUint32(TEST_INTEGER.uint8)
  )).value, { kind: "unsigned", value: BigInt(TEST_INTEGER.uint8) });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.gnuStringIndex,
    encodeUleb(TEST_INTEGER.uint8)
  )).value, { kind: "string-index", value: BigInt(TEST_INTEGER.uint8) });
  assert.deepEqual((await readForm(
    TEST_DWARF.form.gnuAddressIndex,
    encodeUleb(TEST_INTEGER.uint8)
  )).value, { kind: "unsigned", value: BigInt(TEST_INTEGER.uint8) });
});

void test("readDwarfForm follows indirect forms and rejects unknown forms", async () => {
  assert.deepEqual((await readForm(TEST_DWARF.form.indirect, concatenateBytes(
    encodeUleb(TEST_DWARF.form.data1),
    encodeUint8(TEST_INTEGER.uint8)
  ))).value,
    { kind: "unsigned", value: BigInt(TEST_INTEGER.uint8) });
  const unsupported = await readForm(TEST_DWARF.invalid.form, []);
  assert.equal(unsupported.value, null);
  assert.ok(unsupported.issues[0]?.includes("Unsupported DWARF form"));
});
