"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { isMostlyText, toAsciiPrefix } from "../../analyzers/probes/text-heuristics.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);

void test("toAsciiPrefix stops at NUL and length limit", () => {
  const bytes = new Uint8Array([0x41, 0x42, 0x00, 0x43]);
  assert.strictEqual(toAsciiPrefix(dvFrom(bytes), 10), "AB");
  assert.strictEqual(toAsciiPrefix(dvFrom([0x41, 0x42, 0x43, 0x44]), 2), "AB");
});

void test("isMostlyText flags printable-heavy buffers", () => {
  const text = new TextEncoder().encode("hello world\n");
  assert.strictEqual(isMostlyText(dvFrom(text)), true);
  const binary = new Uint8Array([0x00, 0xff, 0x10, 0x00]);
  assert.strictEqual(isMostlyText(dvFrom(binary)), false);
});
