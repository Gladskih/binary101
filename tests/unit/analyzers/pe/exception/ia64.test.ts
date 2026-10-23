import assert from "node:assert/strict";
import { test } from "node:test";
import { parseIa64ExceptionTable } from "../../../../../analyzers/pe/exception/ia64.js";
import { ia64ExceptionRows, ia64ExceptionMap } from "../../../../fixtures/pe-ia64-exception.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const image = new MockFile(new Uint8Array(512));

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
  assert.deepEqual(parsed.issues, ["IA64 unwind payloads are not decoded; handler and chaining information is unavailable."]);
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
  const parsed = await parseIa64ExceptionTable({ size: 512,
    read: async () => { throw new Error("unexpected xdata read"); },
    readBytes: async () => { throw new Error("unexpected xdata read"); }
  }, source, source.size, ia64ExceptionMap);

  assert.equal(parsed.uniqueUnwindInfoCount, 1);
  assert.match(parsed.issues[0]!, /not decoded/);
});

void test("IA64 accepts equal sorted starts without a sorting warning", async () => {
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0x1180], [0x1000, 0x1080, 0x1180]]);
  const parsed = await parseIa64ExceptionTable(image, source, source.size, ia64ExceptionMap);

  assert.equal(parsed.functionCount, 2);
  assert.equal(parsed.issues.length, 1);
  assert.doesNotMatch(parsed.issues.join(" | "), /not sorted/);
});

void test("IA64 reports absent references without claiming decoded payloads", async () => {
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0], [0, 0, 0x1180]]);
  const parsed = await parseIa64ExceptionTable(image, source, source.size, ia64ExceptionMap);

  assert.equal(parsed.functionCount, 2);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.equal(parsed.uniqueUnwindInfoCount, 0);
  assert.deepEqual(parsed.issues, ["IA64 unwind information RVA is 0."]);
});

void test("IA64 maps references to file offset zero but rejects EOF", async () => {
  const source = ia64ExceptionRows([[0x1000, 0x1040, 0x1180], [0x1040, 0x1080, 0x1190]]);
  const parsed = await parseIa64ExceptionTable(image, source, source.size,
    rva => rva === 0x1180 ? 0 : rva === 0x1190 ? image.size : ia64ExceptionMap(rva));

  assert.equal(parsed.uniqueUnwindInfoCount, 1);
  assert.match(parsed.issues.join(" | "), /could not be mapped/);
});
