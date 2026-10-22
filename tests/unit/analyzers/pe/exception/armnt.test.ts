import assert from "node:assert/strict";
import { test } from "node:test";
import { parseArmntExceptionDirectory, parseArmntExceptionTable } from "../../../../../analyzers/pe/exception/armnt.js";
import { armntPackedWord, createArmntTable, ARMNT_FIXTURE_XDATA_RVA } from "../../../../fixtures/pe-armnt-unwind.js";
import { MockFile } from "../../../../helpers/mock-file.js";

void test("ARMNT table normalizes Thumb markers and retains packed fragments", async () => {
  const { file, source, code } = createArmntTable([armntPackedWord(), armntPackedWord(4, 2)]);
  const parsed = await parseArmntExceptionTable(file, source, source.size, rva => rva);

  assert.deepEqual(parsed.beginRvas, [code, code + 4]);
  assert.deepEqual(parsed.rangeLengths, [4, 4]);
  assert.equal(parsed.armntPacked?.returnKinds.branch16, 2);
  assert.equal(parsed.fragmentEntryCount, 1);
  assert.equal(parsed.handlerUnwindInfoCount, 0);
  assert.equal(parsed.uniqueUnwindInfoCount, 2);
  assert.deepEqual(parsed.issues, []);
});

void test("ARMNT directory reuses shared xdata and preserves its actual instruction ranges", async () => {
  const fixture = createArmntTable([ARMNT_FIXTURE_XDATA_RVA, ARMNT_FIXTURE_XDATA_RVA]);
  const parsed = await parseArmntExceptionDirectory(fixture.file, [fixture.directory], rva => rva);

  assert.equal(parsed?.functionCount, 2);
  assert.equal(parsed?.uniqueUnwindInfoCount, 1);
  assert.equal(parsed?.armntPacked, undefined);
  assert.deepEqual(parsed?.beginRvas, [fixture.code, fixture.code + 4]);
  assert.deepEqual(parsed?.issues, []);
});

void test("ARMNT retains other rows when an unwind encoding or function range is invalid", async () => {
  const { file, source, code } = createArmntTable([3, armntPackedWord(0), armntPackedWord()]);
  const parsed = await parseArmntExceptionTable(file, source, source.size, rva => rva);

  assert.equal(parsed.functionCount, 3);
  assert.equal(parsed.invalidEntryCount, 2);
  assert.deepEqual(parsed.beginRvas, [code + 8]);
  assert.match(parsed.issues.join(" | "), /reserved/);
});

for (const [rva, size, mapped, expected] of [
  [0, 0, 0, null], [0, 8, 0, ["Exception directory has a non-zero size but RVA is 0."]],
  [8, 8, null, ["Exception directory RVA could not be mapped to a file offset."]],
  [8, 8, -1, ["Exception directory location is outside the file."]],
  [8, 8, 0.5, ["Exception directory location is outside the file."]],
  [8, 8, 16, ["Exception directory location is outside the file."]],
  [8, 0, 0, ["Exception directory size is smaller than one ARMNT .pdata entry (8 bytes)."]]
] as const) {
  void test(`ARMNT directory validates location ${rva}, ${size}, ${mapped}`, async () => {
    const parsed = await parseArmntExceptionDirectory(new MockFile(new Uint8Array(16)),
      [{ name: "EXCEPTION", rva, size }], () => mapped);

    assert.deepEqual(parsed?.issues ?? null, expected);
  });
}

void test("ARMNT directory is absent when no EXCEPTION entry exists", async () => {
  assert.equal(await parseArmntExceptionDirectory(new MockFile(new Uint8Array(0)), [], () => null), null);
});

void test("ARMNT directory selects its actual entry and accepts physical file offset zero", async () => {
  const fixture = createArmntTable([armntPackedWord()]);
  const bytes = fixture.file.data.slice();
  bytes.copyWithin(0, fixture.directory.rva, fixture.directory.rva + fixture.directory.size);
  const parsed = await parseArmntExceptionDirectory(new MockFile(bytes),
    [{ name: "DEBUG", rva: 32, size: 8 }, fixture.directory],
    rva => rva >= fixture.directory.rva && rva < fixture.directory.rva + fixture.directory.size
      ? rva - fixture.directory.rva : rva);

  assert.deepEqual(parsed?.beginRvas, [fixture.code]);
  assert.deepEqual(parsed?.issues, []);
});

void test("ARMNT normalizes handler pointers, counts references, and decodes shared metadata once", async context => {
  const fixture = createArmntTable([ARMNT_FIXTURE_XDATA_RVA, ARMNT_FIXTURE_XDATA_RVA]);
  const bytes = fixture.file.data.slice();
  const view = new DataView(bytes.buffer);
  view.setUint32(fixture.xdata, 2 | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 28), true);
  view.setUint32(fixture.xdata + 8, fixture.code + 1, true);
  const file = new MockFile(bytes);
  const calls = context.mock.method(file, "read");
  const parsed = await parseArmntExceptionTable(file, fixture.source, fixture.source.size, rva => rva);

  assert.equal(parsed.handlerUnwindInfoCount, 2);
  assert.deepEqual(parsed.handlerRvas, [fixture.code]);
  assert.equal(parsed.fragmentEntryCount, 2);
  assert.equal(calls.mock.callCount(), 2);
  assert.deepEqual(parsed.issues, []);
});

void test("ARMNT reports descending starts once and accepts repeated starts", async () => {
  const fixture = createArmntTable([armntPackedWord(), armntPackedWord(), armntPackedWord(), armntPackedWord()]);
  const bytes = fixture.source.data.slice();
  const view = new DataView(bytes.buffer);
  [fixture.code + 8, fixture.code + 4, fixture.code + 4, fixture.code]
    .forEach((begin, index) => view.setUint32(index * 8, begin + 1, true));
  const parsed = await parseArmntExceptionTable(fixture.file, new MockFile(bytes), bytes.length, rva => rva);

  assert.deepEqual(parsed.beginRvas, [fixture.code + 8, fixture.code + 4, fixture.code + 4, fixture.code]);
  assert.deepEqual(parsed.issues, ["ARMNT .pdata entries are not sorted by function start RVA."]);
});

void test("ARMNT zero handler declarations do not become code seeds", async () => {
  const fixture = createArmntTable([ARMNT_FIXTURE_XDATA_RVA]);
  const bytes = fixture.file.data.slice();
  new DataView(bytes.buffer).setUint32(fixture.xdata, 2 | (1 << 20) | (1 << 21) | (1 << 28), true);
  const parsed = await parseArmntExceptionTable(new MockFile(bytes), fixture.source, fixture.source.size, rva => rva);

  assert.equal(parsed.handlerUnwindInfoCount, 1);
  assert.deepEqual(parsed.handlerRvas, []);
  assert.deepEqual(parsed.issues, ["ARMNT .xdata declares exception data with handler RVA 0."]);
});

void test("ARMNT PE32 debug dispatch decodes an unmapped copy without a table origin", async () => {
  const { createPeWithRawArmntExceptionCopy } = await import("../../../../fixtures/pe-armnt-debug-file.js");
  const { parsePeHeaders } = await import("../../../../../analyzers/pe/core/index.js");
  const { parseDebugDirectory } = await import("../../../../../analyzers/pe/debug/directory.js");
  const file = createPeWithRawArmntExceptionCopy();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const parsed = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const exception = parsed.entries[0]?.exception;

  assert.equal(core.opt?.Magic, 0x10b);
  assert.equal(core.coff.Machine, 0x1c4);
  assert.deepEqual(exception?.beginRvas, [0x1000, 0x1040]);
  assert.deepEqual(exception?.rangeLengths, [64, 64]);
  assert.equal(exception?.armntPacked?.frameChainCount, 1);
  assert.equal(exception?.armntPacked?.prologFoldingCount, 1);
  assert.equal(exception?.fragmentEntryCount, 1);
  assert.deepEqual(exception?.issues, []);
});

for (const [size, expected] of [
  [-1, ["Exception directory size is smaller than one ARMNT .pdata entry (8 bytes)."]],
  [0, ["Exception directory size is smaller than one ARMNT .pdata entry (8 bytes)."]],
  [7, ["Exception directory size is smaller than one ARMNT .pdata entry (8 bytes)."]],
  [8, ["Exception directory is truncated; some ARMNT .pdata entries are missing.",
    "Exception directory does not contain a complete ARMNT .pdata entry."]],
  [9, ["Exception directory size is not a multiple of ARMNT .pdata entry size (8 bytes).",
    "Exception directory is truncated; some ARMNT .pdata entries are missing.",
    "Exception directory does not contain a complete ARMNT .pdata entry."]],
  [NaN, ["Exception directory size is not a multiple of ARMNT .pdata entry size (8 bytes).",
    "RUNTIME_FUNCTION entry count is invalid.", "Exception directory does not contain a complete ARMNT .pdata entry."]],
  [Infinity, ["Exception directory size is not a multiple of ARMNT .pdata entry size (8 bytes).",
    "RUNTIME_FUNCTION entry count is invalid.", "Exception directory does not contain a complete ARMNT .pdata entry."]]
] as const) {
  void test(`ARMNT table diagnoses missing bytes or invalid extent ${size}`, async () => {
    const file = new MockFile(new Uint8Array(0));
    const parsed = await parseArmntExceptionTable(file, file, size, () => null);

    assert.equal(parsed.functionCount, 0);
    assert.deepEqual(parsed.issues, expected);
  });
}

void test("ARMNT accepts equal starts before any descending entry", async () => {
  const fixture = createArmntTable([armntPackedWord(), armntPackedWord()]);
  const bytes = fixture.source.data.slice();
  new DataView(bytes.buffer).setUint32(8, fixture.code + 1, true);
  const parsed = await parseArmntExceptionTable(fixture.file, new MockFile(bytes), bytes.length, rva => rva);

  assert.deepEqual(parsed.beginRvas, [fixture.code, fixture.code]);
  assert.deepEqual(parsed.issues, []);
});
