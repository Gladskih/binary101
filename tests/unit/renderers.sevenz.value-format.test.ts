"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  formatOffset,
  formatSize,
  formatSizeDetailed,
  formatRatio
} from "../../renderers/sevenz/value-format.js";

void test("formatOffset renders null, numbers, bigint and negatives", () => {
  assert.strictEqual(formatOffset(null), "-");
  assert.strictEqual(formatOffset(0), "0x00000000");
  assert.strictEqual(formatOffset(0x1234), "0x00001234");
  assert.strictEqual(formatOffset(0x100000000n), "0x100000000");

  // Negative numbers are treated as unsigned 32-bit values.
  assert.strictEqual(formatOffset(-1), "0xffffffff");
});

void test("formatSize renders small, bigint and huge values", () => {
  assert.strictEqual(formatSize(0), "0 B (0 bytes)");
  assert.strictEqual(formatSize(1024), "1 KB (1024 bytes)");

  // Small bigint goes through the human-size formatter.
  assert.strictEqual(formatSize(1000n), "1000 B (1000 bytes)");

  // Very large bigint is rendered as a raw byte count string.
  const big = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
  assert.strictEqual(formatSize(big), `${big.toString()} bytes`);

  // Negative sizes are not expected but should still render deterministically.
  const negative = formatSize(-512);
  assert.match(negative, /-512/);
});

void test("formatSizeDetailed clamps unsafe sizes and formats bigints", () => {
  assert.strictEqual(formatSizeDetailed(2048n), "2 KB (2048 bytes)");

  // Huge bigint stays as a raw byte count.
  const huge = 2n ** 63n;
  assert.strictEqual(formatSizeDetailed(huge), `${huge.toString()} bytes`);

  // Negative bigint is routed through the human-size formatter.
  const negativeBig = -5n;
  const negativeDetailed = formatSizeDetailed(negativeBig);
  assert.match(negativeDetailed, /-5/);
});

void test("formatRatio handles normal, zero and invalid values", () => {
  assert.strictEqual(formatRatio(0.0), "0.0%");
  assert.strictEqual(formatRatio(12.345), "12.3%");

  // Null or non-finite ratios are rendered as a dash.
  assert.strictEqual(formatRatio(null), "-");
  assert.strictEqual(formatRatio(Number.NaN), "-");
  assert.strictEqual(formatRatio(Number.POSITIVE_INFINITY), "-");
  assert.strictEqual(formatRatio(Number.NEGATIVE_INFINITY), "-");
});