import assert from "node:assert/strict";
import { test } from "node:test";

import {
  alignUpTo,
  bufferToHex,
  collectPrintableRuns,
  formatHumanSize,
  formatUnixSecondsOrDash
} from "../../binary-utils.js";

test("formatHumanSize reports readable units", () => {
  assert.strictEqual(formatHumanSize(0), "0 B (0 bytes)");
  assert.strictEqual(formatHumanSize(1536), "1.5 KB (1536 bytes)");
  assert.strictEqual(formatHumanSize(1048576), "1 MB (1048576 bytes)");
});

test("alignUpTo rounds values up to the requested boundary", () => {
  assert.strictEqual(alignUpTo(0x1234, 0x1000), 0x2000);
  assert.strictEqual(alignUpTo(0x1000, 0x1000), 0x1000);
  assert.strictEqual(alignUpTo(5, 0), 5);
});

test("collectPrintableRuns returns only long enough sequences", () => {
  const bytes = new Uint8Array([0x41, 0x42, 0x43, 0x00, 0x44, 0x45, 0x10, 0x46]);
  assert.deepStrictEqual(collectPrintableRuns(bytes, 2), ["ABC", "DE"]);
});

test("formatUnixSecondsOrDash handles invalid and unusual timestamps", () => {
  assert.strictEqual(formatUnixSecondsOrDash(-1), "-");
  assert.strictEqual(formatUnixSecondsOrDash(NaN), "-");

  const normalIso = formatUnixSecondsOrDash(Date.UTC(2024, 0, 1) / 1000);
  assert.ok(normalIso.startsWith("2024-01-01T00:00:00.000Z"));

  const farFuture = formatUnixSecondsOrDash(Date.UTC(2200, 0, 1) / 1000);
  assert.ok(farFuture.endsWith("(unusual)"));
});

test("bufferToHex converts raw bytes into hex", () => {
  const buffer = new Uint8Array([0x00, 0x10, 0xff]).buffer;
  assert.strictEqual(bufferToHex(buffer), "0010ff");
});
