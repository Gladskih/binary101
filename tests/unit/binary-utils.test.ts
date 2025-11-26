import assert from "node:assert/strict";
import { test } from "node:test";

import {
  alignUpTo,
  bufferToHex,
  collectPrintableRuns,
  formatHumanSize,
  formatUnixSecondsOrDash,
  nowIsoString,
  readAsciiString,
  toHex32,
  toHex64
} from "../../binary-utils.js";

void test("formatHumanSize reports readable units", () => {
  assert.strictEqual(formatHumanSize(0), "0 B (0 bytes)");
  assert.strictEqual(formatHumanSize(1536), "1.5 KB (1536 bytes)");
  assert.strictEqual(formatHumanSize(1048576), "1 MB (1048576 bytes)");
});

void test("alignUpTo rounds values up to the requested boundary", () => {
  assert.strictEqual(alignUpTo(0x1234, 0x1000), 0x2000);
  assert.strictEqual(alignUpTo(0x1000, 0x1000), 0x1000);
  assert.strictEqual(alignUpTo(5, 0), 5);
});

void test("collectPrintableRuns returns only long enough sequences", () => {
  const bytes = new Uint8Array([0x41, 0x42, 0x43, 0x00, 0x44, 0x45, 0x10, 0x46]);
  assert.deepStrictEqual(collectPrintableRuns(bytes, 2), ["ABC", "DE"]);
});

void test("collectPrintableRuns splits very long runs to stay bounded", () => {
  const bytes = new Uint8Array(4100).fill(0x41); // 'A'
  const runs = collectPrintableRuns(bytes, 2);
  assert.deepStrictEqual(runs.map(run => run.length), [4097, 3]);
});

void test("formatUnixSecondsOrDash handles invalid and unusual timestamps", () => {
  assert.strictEqual(formatUnixSecondsOrDash(-1), "-");
  assert.strictEqual(formatUnixSecondsOrDash(NaN), "-");

  const normalIso = formatUnixSecondsOrDash(Date.UTC(2024, 0, 1) / 1000);
  assert.ok(normalIso.startsWith("2024-01-01T00:00:00.000Z"));

  const farFuture = formatUnixSecondsOrDash(Date.UTC(2200, 0, 1) / 1000);
  assert.ok(farFuture.endsWith("(unusual)"));
});

void test("bufferToHex converts raw bytes into hex", () => {
  const buffer = new Uint8Array([0x00, 0x10, 0xff]).buffer;
  assert.strictEqual(bufferToHex(buffer), "0010ff");
});

void test("readAsciiString stops at NUL and respects bounds", () => {
  const bytes = new Uint8Array([0x41, 0x42, 0x00, 0x43]);
  const view = new DataView(bytes.buffer);
  assert.strictEqual(readAsciiString(view, 0, 10), "AB");
  assert.strictEqual(readAsciiString(view, 1, 2), "B");
});

void test("toHex32 masks to unsigned and pads width", () => {
  assert.strictEqual(toHex32(-1), "0xffffffff");
  assert.strictEqual(toHex32(0x1a, 4), "0x001a");
});

void test("toHex64 renders 64-bit values", () => {
  assert.strictEqual(toHex64(0x1fffffffffffffn), "0x1fffffffffffff");
});

void test("nowIsoString returns a valid ISO timestamp", () => {
  const iso = nowIsoString();
  assert.ok(!Number.isNaN(Date.parse(iso)));
  assert.ok(iso.endsWith("Z"));
});