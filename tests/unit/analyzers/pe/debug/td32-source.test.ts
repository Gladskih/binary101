import assert from "node:assert/strict";
import { test } from "node:test";
import { readTd32Source } from "../../../../../analyzers/pe/debug/td32-source.js";
import { td32Source, td32MultiSource } from "../../../../fixtures/pe-td32.js";
import { legacyReader, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("TD32 source files use unaligned name indices and parallel line arrays", async () => {
  const warnings: string[] = [];

  const parsed = await readTd32Source(legacyReader(td32Source(), warnings));

  assert.deepEqual(parsed, { kind: "source", files: [{ nameIndex: 3, segments: [{ segment: 1,
    start: 16, end: 48, lines: [{ offset: 16, line: 7 }, { offset: 24, line: 9 }] }] }] });
  assert.deepEqual(warnings, []);
});

void test("TD32 reads independent parallel arrays for every source segment", async () => {
  const warnings: string[] = [];

  const parsed = await readTd32Source(legacyReader(td32MultiSource(), warnings));

  assert.deepEqual(parsed.files[0]!.segments, [
    { segment: 1, start: 16, end: 24, lines: [{ offset: 16, line: 7 }, { offset: 24, line: 9 }] },
    { segment: 2, start: 32, end: 40, lines: [{ offset: 32, line: 11 }, { offset: 40, line: 13 }] }
  ]);
  assert.deepEqual(warnings, []);
});

void test("TD32 separately bounds-checks module file and segment arrays", async () => {
  await assert.rejects(readTd32Source(legacyReader([1, 0, 0, 0, 0, 0, 0])), /module arrays/);
  await assert.rejects(readTd32Source(legacyReader([0, 0, 1, 0, ...new Array<number>(9).fill(0)])), /module arrays/);
  assert.deepEqual(await readTd32Source(legacyReader([1, 0, 0, 0, ...legacyU32(8), 0, 0, ...legacyU32(3)])),
    { kind: "source", files: [{ nameIndex: 3, segments: [] }] });
});

void test("TD32 accepts equal source bounds and diagnoses a single line on either side of a range", async () => {
  const bytes = td32Source();
  bytes.set(legacyU32(16), 34);
  bytes.set(legacyU32(16), 46);
  const warnings: string[] = [];

  await readTd32Source(legacyReader(bytes, warnings));

  assert.deepEqual(warnings, []);
  bytes.set(legacyU32(24), 46);
  await readTd32Source(legacyReader(bytes, warnings));
  assert.deepEqual(warnings, ["TD32 line lies outside its source range."]);
  warnings.length = 0;
  bytes.set(legacyU32(24), 30);
  bytes.set(legacyU32(24), 34);
  await readTd32Source(legacyReader(bytes, warnings));
  assert.deepEqual(warnings, ["TD32 line lies outside its source range."]);
});

void test("TD32 source cache reuses files and lines but retains independent source ranges", async () => {
  const bytes = new Uint8Array(100);
  bytes.set(td32Source());
  bytes[0] = 3;
  bytes[2] = 0;
  bytes.set(legacyU32(20), 8);
  bytes.set(legacyU32(60), 12);
  bytes.set([1, 0, ...legacyU32(2), ...legacyU32(38), ...legacyU32(0), ...legacyU32(100)], 60);
  const warnings: string[] = [];

  const parsed = await readTd32Source(legacyReader(bytes, warnings));

  assert.equal(parsed.files[0], parsed.files[1]);
  assert.equal(parsed.files[0]!.segments[0]!.lines, parsed.files[2]!.segments[0]!.lines);
  assert.equal(parsed.files[2]!.segments[0]!.start, 0);
  assert.equal(parsed.files[2]!.segments[0]!.end, 100);
  assert.deepEqual(warnings, []);
});

void test("TD32 diagnoses reversed ranges and out-of-range source lines", async () => {
  const bytes = td32Source();
  bytes.set(legacyU32(30), 30);
  bytes.set(legacyU32(20), 34);
  const warnings: string[] = [];

  await readTd32Source(legacyReader(bytes, warnings));

  assert.match(warnings.join(" | "), /range is reversed/);
  assert.match(warnings.join(" | "), /outside its source range/);
});

void test("TD32 checks every nested source table before reading arrays", async () => {
  await assert.rejects(readTd32Source(legacyReader([])), /bounds/);
  await assert.rejects(readTd32Source(legacyReader([1, 0, 1, 0])), /module arrays/);
  await assert.rejects(readTd32Source(legacyReader(td32Source().subarray(0, 25))), /bounds/);
  await assert.rejects(readTd32Source(legacyReader(td32Source().subarray(0, 37))), /file arrays/);
  await assert.rejects(readTd32Source(legacyReader(td32Source().subarray(0, 41))), /bounds/);
  await assert.rejects(readTd32Source(legacyReader(td32Source().subarray(0, 53))), /line pairs/);
  assert.deepEqual(await readTd32Source(legacyReader([0, 0, 0, 0])), { kind: "source", files: [] });
});
