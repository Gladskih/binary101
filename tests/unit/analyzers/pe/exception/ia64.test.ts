import assert from "node:assert/strict";
import { test } from "node:test";
import { parseIa64ExceptionTable } from "../../../../../analyzers/pe/exception/ia64.js";
import { ia64ExceptionRows, ia64ExceptionMap, ia64ExceptionImage } from "../../../../fixtures/pe-ia64-exception.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const image = ia64ExceptionImage();

void test("IA64 decodes three DWORD RVAs and deduplicates shared unwind references", async () => {
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0x1180], [0x1040, 0x1080, 0x1180],
    [0x1080, 0x1100, 0x1190]]);
  const parsed = await parseIa64ExceptionTable(image, source, source.size, ia64ExceptionMap);

  assert.equal(parsed.format, "ia64");
  assert.equal(parsed.functionCount, 3);
  assert.deepEqual(parsed.beginRvas, [0x1000, 0x1040, 0x1080]);
  assert.deepEqual(parsed.rangeLengths, [64, 64, 128]);
  assert.equal(parsed.invalidEntryCount, 0);
  assert.equal(parsed.uniqueUnwindInfoCount, 2);
  assert.deepEqual(parsed.handlerRvas, []);
  assert.equal(parsed.handlerUnwindInfoCount, 0);
  assert.deepEqual(parsed.ia64Unwind, { versions: [{ version: 3, count: 2 }],
    descriptorCounts: { "Empty prologues / padding": 16 },
    regionLengths: { prologue: { count: 16, minimumSlots: "0", maximumSlots: "0" }, body: { count: 0 } },
    savedRegisterRules: {}, registerSaveLocations: {}, spillScheduleSlots: {}, abiContextCounts: {},
    exceptionHandlerCount: 0, unwindHandlerCount: 0 });
  assert.deepEqual(parsed.issues, []);
});

void test("IA64 preserves valid neighbors around empty, reversed and unmapped ranges", async () => {
  const source = ia64ExceptionRows([[0, 16, 0x1180], [0x1040, 0x1040, 0x1180],
    [0x1080, 0x1040, 0x1180], [0x11f0, 0x1210, 0x1180], [0x1000, 0x1040, 0x1180]]);
  const parsed = await parseIa64ExceptionTable(image, source, source.size, ia64ExceptionMap);

  assert.equal(parsed.functionCount, 5);
  assert.equal(parsed.invalidEntryCount, 4);
  assert.deepEqual(parsed.beginRvas, [0x1000]);
  assert.deepEqual(parsed.rangeLengths, [64]);
  assert.equal(parsed.uniqueUnwindInfoCount, 1);
});

void test("IA64 diagnoses unsorted rows while retaining equal and descending starts", async () => {
  const source = ia64ExceptionRows([[0x1080, 0x10a0, 0x1180], [0x1080, 0x10b0, 0x1180],
    [0x1000, 0x1040, 0x1180], [0x1040, 0x1080, 0x1180], [0x1000, 0x1040, 0x1180]]);
  const parsed = await parseIa64ExceptionTable(image, source, source.size, ia64ExceptionMap);

  assert.equal(parsed.functionCount, 5);
  assert.equal(parsed.invalidEntryCount, 0);
  assert.deepEqual(parsed.beginRvas, [0x1080, 0x1080, 0x1000, 0x1040, 0x1000]);
  assert.equal(parsed.issues.filter(issue => /not sorted/.test(issue)).length, 1);
});

void test("IA64 validates unwind references independently of function ranges", async () => {
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0], [0x1040, 0x1080, 0x1300],
    [0x1080, 0x10c0, 0x11ff], [0x10c0, 0x1100, 0x1180]]);
  const parsed = await parseIa64ExceptionTable(image, source, source.size, ia64ExceptionMap);

  assert.equal(parsed.invalidEntryCount, 0);
  assert.equal(parsed.uniqueUnwindInfoCount, 2);
  assert.match(parsed.issues.join(" | "), /unwind information RVA is 0/);
  assert.match(parsed.issues.join(" | "), /unwind information RVA could not be mapped/);
  assert.deepEqual(parsed.ia64Unwind?.versions, [{ version: 3, count: 1 }]);
});

for (const size of [-1, 0, 11, 12.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
  void test(`IA64 rejects invalid table size ${size}`, async () => {
    const parsed = await parseIa64ExceptionTable(image, image, size, ia64ExceptionMap);

    assert.equal(parsed.functionCount, 0);
    assert.match(parsed.issues[0]!, /smaller than one entry or invalid/);
  });
}

void test("IA64 bounds complete rows by source size and diagnoses partial tails", async () => {
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0x1180]]);
  const parsed = await parseIa64ExceptionTable(image, source, source.size + 13, ia64ExceptionMap);

  assert.equal(parsed.functionCount, 1);
  assert.equal(parsed.invalidEntryCount, 0);
  assert.match(parsed.issues.join(" | "), /not a multiple/);
  assert.match(parsed.issues.join(" | "), /truncated/);
});

void test("IA64 never reads unwind bytes using the incompatible AMD64 decoder", async () => {
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0x1180]]);
  const offsets: number[] = [];
  const parsed = await parseIa64ExceptionTable({ size: 512,
    read: async offset => {
      offsets.push(offset);
      return new DataView(Uint8Array.from([1, 0, 3, 0, 1, 0, 0, 0]).buffer);
    },
    readBytes: async () => { throw new Error("unexpected xdata read"); }
  }, source, source.size, ia64ExceptionMap);

  assert.equal(parsed.uniqueUnwindInfoCount, 1);
  assert.match(parsed.issues[0]!, /version 1 is not decoded/);
  assert.deepEqual(offsets, [0x180]);
  assert.equal(parsed.handlerUnwindInfoCount, 0);
  assert.deepEqual(parsed.ia64Unwind?.versions, [{ version: 1, count: 1 }]);
});

void test("IA64 accepts equal sorted starts without a sorting warning", async () => {
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0x1180], [0x1000, 0x1080, 0x1180]]);
  const parsed = await parseIa64ExceptionTable(image, source, source.size, ia64ExceptionMap);

  assert.equal(parsed.functionCount, 2);
  assert.equal(parsed.issues.length, 0);
  assert.doesNotMatch(parsed.issues.join(" | "), /not sorted/);
});

void test("IA64 reports absent references without claiming decoded payloads", async () => {
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0], [0, 0, 0x1180]]);
  const parsed = await parseIa64ExceptionTable(image, source, source.size, ia64ExceptionMap);

  assert.equal(parsed.functionCount, 2);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.equal(parsed.uniqueUnwindInfoCount, 0);
  assert.equal(parsed.ia64Unwind, undefined);
  assert.deepEqual(parsed.issues, ["IA64 unwind information RVA is 0."]);
});

void test("IA64 maps references to file offset zero but rejects EOF", async () => {
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0x1180], [0x1040, 0x1080, 0x1190]]);
  const parsed = await parseIa64ExceptionTable(image, source, source.size,
    rva => rva === 0x1180 ? 0 : rva === 0x1190 ? image.size : ia64ExceptionMap(rva));

  assert.equal(parsed.uniqueUnwindInfoCount, 1);
  assert.match(parsed.issues.join(" | "), /could not be mapped/);
});

void test("IA64 reads each shared block once and combines flags and exact stack sizes", async () => {
  const bytes = image.data.slice();
  const view = new DataView(bytes.buffer);
  view.setUint16(0x182, 1, true);
  view.setUint16(0x192, 2, true);
  view.setUint16(0x1a0, 3, true);
  view.setUint16(0x1a2, 3, true);
  bytes.set([1, 0xe0, 0, 1], 0x188);
  bytes.set([1, 0xe0, 0, 3], 0x198);
  const file = new MockFile(bytes);
  const calls: number[] = [];
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0x1180], [0x1040, 0x1080, 0x1180],
    [0x1080, 0x10c0, 0x1190], [0x10c0, 0x1100, 0x11a0]]);
  const parsed = await parseIa64ExceptionTable({ size: file.size,
    read: (offset, size) => { calls.push(offset); return file.read(offset, size); },
    readBytes: (offset, size) => file.readBytes(offset, size) }, source, source.size, ia64ExceptionMap);

  assert.equal(parsed.handlerUnwindInfoCount, 3);
  assert.equal(parsed.ia64Unwind?.exceptionHandlerCount, 2);
  assert.equal(parsed.ia64Unwind?.unwindHandlerCount, 2);
  assert.equal(parsed.ia64Unwind?.maximumFixedStackBytes, 48);
  assert.deepEqual(parsed.ia64Unwind?.versions, [{ version: 3, count: 3 }]);
  assert.deepEqual(parsed.ia64Unwind?.descriptorCounts, {
    "Prologue regions": 2, "Fixed stack allocations": 2, "Empty prologues / padding": 8 });
  assert.equal(parsed.ia64Unwind?.regionLengths.prologue.count, 10);
  assert.equal(parsed.ia64Unwind?.regionLengths.prologue.minimumSlots, "0");
  assert.equal(parsed.ia64Unwind?.regionLengths.prologue.maximumSlots, "1");
  assert.deepEqual(calls, [0x180, 0x188, 0x190, 0x198, 0x1a0]);
  assert.deepEqual(parsed.issues, []);
});

void test("IA64 merges bounded operand summaries from distinct unwind blocks", async () => {
  const bytes = image.data.slice();
  bytes.set([1, 0x8f], 0x188);
  bytes.set([1, 0xb0, 0x80], 0x198);
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0x1180], [0x1040, 0x1080, 0x1190]]);
  const parsed = await parseIa64ExceptionTable(new MockFile(bytes), source, source.size, ia64ExceptionMap);

  assert.deepEqual(parsed.ia64Unwind?.savedRegisterRules, {
    "branch registers in memory": 4,
    "rp in general register": 1
  });
  assert.equal(parsed.ia64Unwind?.regionLengths.prologue.count, 13);
  assert.deepEqual(parsed.issues, []);
});

void test("IA64 retains zero fixed-stack sizes in aggregate statistics", async () => {
  const bytes = image.data.slice();
  bytes.set([1, 0xe0, 0, 0], 0x188);
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0x1180]]);
  const parsed = await parseIa64ExceptionTable(new MockFile(bytes), source, source.size, ia64ExceptionMap);

  assert.equal(parsed.ia64Unwind?.maximumFixedStackBytes, 0);
});

for (const [flags, exceptionCount, unwindCount] of [[1, 1, 0], [2, 0, 1]] as const) {
  void test(`IA64 distinguishes exception and cleanup flag ${flags}`, async () => {
    const bytes = image.data.slice();
    new DataView(bytes.buffer).setUint16(0x182, flags, true);
    const source = ia64ExceptionRows([[0x1000, 0x1040, 0x1180]]);
    const parsed = await parseIa64ExceptionTable(new MockFile(bytes), source, source.size, ia64ExceptionMap);

    assert.equal(parsed.handlerUnwindInfoCount, 1);
    assert.equal(parsed.ia64Unwind?.exceptionHandlerCount, exceptionCount);
    assert.equal(parsed.ia64Unwind?.unwindHandlerCount, unwindCount);
  });
}
