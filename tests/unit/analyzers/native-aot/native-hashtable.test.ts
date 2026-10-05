import assert from "node:assert/strict";
import test from "node:test";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { NativeHashtableReader } from "../../../../analyzers/native-aot/native-hashtable.js";
import { createNativeHashtableFixture } from "../../../helpers/native-hashtable-fixture.js";

void test("enumerates NativeHashtable payloads using byte-sized indices", () => {
  const bytes = createNativeHashtableFixture([Uint8Array.of(42), Uint8Array.of(17)]);
  const issues = new Set<string>();

  assert.deepEqual([...new NativeHashtableReader(bytes).entries(issues)], [
    { offset: 15, lowHashcode: 0 }, { offset: 16, lowHashcode: 1 }
  ]);
  assert.equal(issues.size, 0);
});

void test("enumerates wider NativeHashtable indices", () => {
  const issues = new Set<string>();
  const two = createNativeHashtableFixture([Uint8Array.of(42)], 2);
  const four = createNativeHashtableFixture([Uint8Array.of(42)], 4);

  assert.deepEqual([...new NativeHashtableReader(two).entries(issues)], [{ offset: 11, lowHashcode: 0 }]);
  assert.deepEqual([...new NativeHashtableReader(four).entries(issues)], [{ offset: 15, lowHashcode: 0 }]);
  assert.equal(issues.size, 0);
});

void test("enumerates a multi-byte bucket index beyond byte-addressable offsets", () => {
  const bytes = createNativeHashtableFixture(Array.from({ length: 50 }, () => Uint8Array.of(42)), 2);
  const issues = new Set<string>();

  const entries = [...new NativeHashtableReader(bytes).entries(issues)];

  assert.equal(entries.length, 50);
  assert.equal(entries[0]!.offset, 305);
  assert.equal(entries[49]!.offset, bytes.length - 1);
  assert.equal(issues.size, 0);
});

void test("supports signed backward payload references", () => {
  const issues = new Set<string>();

  assert.deepEqual([...new NativeHashtableReader(Uint8Array.of(0, 3, 5, 42, 0, 252)).entries(issues)],
    [{ offset: 3, lowHashcode: 0 }]);
});

void test("retains readable buckets after a malformed earlier entry", () => {
  const bytes = Uint8Array.of(4, 3, 5, 7, 0, 31, 1, 4, 42, 43);
  const issues = new Set<string>();

  assert.deepEqual([...new NativeHashtableReader(bytes).entries(issues)], [{ offset: 9, lowHashcode: 1 }]);
  assert.match([...issues].join(" "), /compressed integer/);
});

void test("rejects empty input, invalid index selectors and overflowing bucket shifts", () => {
  assert.throws(() => new NativeHashtableReader(new Uint8Array()), /out of bounds|outside/);
  assert.throws(() => new NativeHashtableReader(Uint8Array.of(3)), /header/);
  assert.throws(() => new NativeHashtableReader(Uint8Array.of(128)), /header/);
  assert.throws(() => new NativeHashtableReader(Uint8Array.of(124)), /truncated/);
});

void test("reports reversed and out-of-section bucket ranges", () => {
  const reversed = new Set<string>();
  const excessive = new Set<string>();

  assert.deepEqual([...new NativeHashtableReader(Uint8Array.of(0, 3, 2, 0)).entries(reversed)], []);
  assert.deepEqual([...new NativeHashtableReader(Uint8Array.of(0, 2, 9)).entries(excessive)], []);
  assert.match([...reversed].join(" "), /bucket range/);
  assert.match([...excessive].join(" "), /truncated/);
});

void test("rejects bucket data that overlaps the bucket directory", () => {
  const issues = new Set<string>();

  assert.deepEqual([...new NativeHashtableReader(Uint8Array.of(0, 0, 2)).entries(issues)], []);
  assert.match([...issues].join(" "), /bucket range/);
});

void test("rejects references into the next bucket and outside the section", () => {
  const truncated = new Set<string>();
  const negative = new Set<string>();
  const excessive = new Set<string>();

  assert.deepEqual([...new NativeHashtableReader(Uint8Array.of(0, 2, 4, 0, 15, 0, 0, 0, 0)).entries(truncated)], []);
  assert.deepEqual([...new NativeHashtableReader(Uint8Array.of(0, 2, 4, 0, 244)).entries(negative)], []);
  assert.deepEqual([...new NativeHashtableReader(Uint8Array.of(0, 2, 4, 0, 2)).entries(excessive)], []);
  assert.match([...truncated].join(" "), /truncated or out of bounds/);
  assert.match([...negative].join(" "), /truncated or out of bounds/);
  assert.match([...excessive].join(" "), /truncated or out of bounds/);
});

void test("reads a DataView-backed slice without assuming byteOffset zero", () => {
  const blob = createNativeHashtableFixture([Uint8Array.of(42)]);
  const storage = new Uint8Array(blob.length + 7);
  storage.set(blob, 7);
  const issues = new Set<string>();

  assert.deepEqual([...new NativeHashtableReader(storage.subarray(7)).entries(issues)],
    [{ offset: 9, lowHashcode: 0 }]);
});

void test("handles an empty but structurally valid hashtable", () => {
  const issues = new Set<string>();

  assert.deepEqual([...new NativeHashtableReader(Uint8Array.of(0, 2, 2)).entries(issues)], []);
  assert.equal(issues.size, 0);
});

void test("retains a valid earlier reference when the bucket's declared end exceeds the available bytes", () => {
  const issues = new Set<string>();
  // Payload at byte 3, entry at byte 4, backward reference to byte 3; end declares a missing suffix.
  const bytes = Uint8Array.of(0, 3, 9, 42, 0, 252);

  assert.deepEqual([...new NativeHashtableReader(bytes).entries(issues)], [{ offset: 3, lowHashcode: 0 }]);
  assert.match([...issues].join(" "), /truncated/);
});

void test("NativeHashtable normalizes non-Error entry failures into warnings", context => {
  const bytes = createNativeHashtableFixture([Uint8Array.of(42)]);
  const issues = new Set<string>();
  context.mock.method(NativeFormatReader.prototype, "signed", () => { throw null; });

  assert.deepEqual([...new NativeHashtableReader(bytes).entries(issues)], []);
  assert.deepEqual([...issues], ["NativeHashtable decoding failed."]);
});

void test("rejects a two-byte index directory missing its final byte", () => {
  assert.throws(() => new NativeHashtableReader(Uint8Array.of(1, 4, 0, 4)), /index is truncated/);
});

void test("reads bucket endpoints above 65535 using their four-byte directory width", () => {
  const payloads = Array.from({ length: 10922 }, () => Uint8Array.of(42));
  const issues = new Set<string>();
  const bytes = createNativeHashtableFixture(payloads, 4);

  const entries = [...new NativeHashtableReader(bytes).entries(issues)];

  // Header + two uint32 indices + 10922 six-byte references = payload offset 65541.
  assert.equal(entries.length, 10922);
  assert.equal(entries[0]?.offset, 65541);
  assert.equal(entries[10921]?.offset, 76462);
  assert.deepEqual([...issues], []);
});

void test("rejects a wide bucket range overlapping the final directory byte", () => {
  const issues = new Set<string>();

  assert.deepEqual([...new NativeHashtableReader(Uint8Array.of(1, 3, 0, 3, 0)).entries(issues)], []);
  assert.deepEqual([...issues], ["NativeHashtable bucket range is invalid."]);
});

void test("allows a signed reference to offset zero within the section", () => {
  const issues = new Set<string>();
  // The reference at offset 4 encodes -4; section offset zero is in bounds.
  const bytes = Uint8Array.of(0, 2, 4, 0, 248);

  assert.deepEqual([...new NativeHashtableReader(bytes).entries(issues)], [{ offset: 0, lowHashcode: 0 }]);
  assert.deepEqual([...issues], []);
});
