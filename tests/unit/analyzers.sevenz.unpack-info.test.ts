"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFolder, parseUnpackInfo } from "../../analyzers/sevenz/unpack-info.js";

const makeCtx = (bytes: ArrayLike<number>) => ({
  dv: new DataView(Uint8Array.from(bytes).buffer),
  offset: 0,
  issues: [] as string[]
});

void test("parseFolder reads coder entries without attributes", () => {
  // coderCount=1, coder flags (idSize=1, simple, no attrs), methodId=0x21 (LZMA2)
  const ctx = makeCtx([0x01, 0x01, 0x21]);
  const folder = parseFolder(ctx, ctx.dv.byteLength);
  assert.equal(folder.coders.length, 1);
  const [coder] = folder.coders;
  assert.equal(coder.methodId, "21");
  assert.equal(coder.inStreams, 1);
  assert.equal(coder.outStreams, 1);
  assert.equal(coder.properties, null);
  assert.equal(folder.totalInStreams, 1);
  assert.equal(folder.totalOutStreams, 1);
});

void test("parseUnpackInfo reads folder list, sizes and end marker", () => {
  // UnpackInfo header (0x0b), folderCount=1, external=0,
  // folder: coderCount=1, flags=0x01, methodId=0x21
  // unpack sizes id=0x0c, one size=5, end marker 0x00 (re-read after crc probe)
  const ctx = makeCtx([0x0b, 0x01, 0x00, 0x01, 0x01, 0x21, 0x0c, 0x05, 0x00]);
  const info = parseUnpackInfo(ctx);
  assert.equal(info.external, false);
  assert.equal(info.folders.length, 1);
  assert.equal(info.unpackSizes?.[0]?.[0], 5n);
  assert.equal(ctx.issues.length, 0);
});
