"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  toSafeNumber,
  readByte,
  readEncodedUint64,
  readBoolVector,
  readUint32Le,
  readUint64Le
} from "../../analyzers/sevenz/readers.js";

const makeCtx = (bytes, offset = 0) => ({
  dv: new DataView(Uint8Array.from(bytes).buffer),
  offset,
  issues: []
});

void test("toSafeNumber handles numbers, safe bigints and rejects large bigints", () => {
  assert.equal(toSafeNumber(5), 5);
  assert.equal(toSafeNumber(5n), 5);
  assert.equal(toSafeNumber(BigInt(Number.MAX_SAFE_INTEGER + 1)), null);
  assert.equal(toSafeNumber(null), null);
});

void test("readByte reports truncation when beyond bounds", () => {
  const ctx = makeCtx([0x01], 1);
  assert.equal(readByte(ctx, "Test"), null);
  assert.equal(ctx.issues[0], "Test is truncated.");
});

void test("readEncodedUint64 decodes variable-length values", () => {
  const ctx = makeCtx([0x81, 0x01]); // high bit set -> value 0x101
  assert.equal(readEncodedUint64(ctx), 0x101n);
});

void test("readBoolVector sets issues on overflow", () => {
  const ctx = makeCtx([0x00, 0xff]); // allDefined=0, but only 1 byte present for >8 bits
  const bits = readBoolVector(ctx, 16, ctx.dv.byteLength, "Flags");
  assert.equal(bits?.length, 16);
  assert.ok(ctx.issues[0].includes("Flags"));
});

void test("readUint32Le and readUint64Le clamp offset and report truncation", () => {
  const ctx32 = makeCtx([0x01, 0x02], 0);
  assert.equal(readUint32Le(ctx32, 2, "u32"), null);
  assert.equal(ctx32.offset, 2);
  assert.ok(ctx32.issues[0].includes("u32"));

  const ctx64 = makeCtx([0x01, 0x02, 0x03], 0);
  assert.equal(readUint64Le(ctx64, 3, "u64"), null);
  assert.equal(ctx64.offset, 3);
  assert.ok(ctx64.issues[0].includes("u64"));
});