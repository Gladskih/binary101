"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePackDigests, parsePackInfo } from "../../dist/analyzers/sevenz/pack-info.js";

const makeCtx = bytes => ({
  dv: new DataView(Uint8Array.from(bytes).buffer),
  offset: 0,
  issues: []
});

test("parsePackDigests reads defined flags and CRCs", () => {
  // allDefined = 1, two CRC values little-endian
  const ctx = makeCtx([0x01, 0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x90]);
  const info = parsePackDigests(ctx, 2, ctx.dv.byteLength, "Pack");
  assert.deepEqual(info.definedFlags, [true, true]);
  assert.deepEqual(info.digests, [
    { index: 0, crc: 0x12345678 },
    { index: 1, crc: 0x90abcdef }
  ]);
  assert.equal(info.allDefined, true);
  assert.equal(ctx.issues.length, 0);
});

test("parsePackInfo reads sizes and stops on unknown field ids", () => {
  // packPos=0, numPackStreams=1, one size=5, then unknown field to trigger issue
  const ctx = makeCtx([0x00, 0x01, 0x09, 0x05, 0x0b]);
  const info = parsePackInfo(ctx);
  assert.deepEqual(info.packSizes, [5n]);
  assert.equal(info.packPos, 0n);
  assert.equal(info.numPackStreams, 1n);
  assert.equal(ctx.issues.length, 1);
  assert.match(ctx.issues[0], /Unknown PackInfo field id/);
});
