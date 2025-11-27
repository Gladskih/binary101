"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseStreamsInfo, parseSubStreamsInfo } from "../../analyzers/sevenz/streams-info.js";

const makeCtx = (bytes: ArrayLike<number>) => ({
  dv: new DataView(Uint8Array.from(bytes).buffer),
  offset: 0,
  issues: [] as string[]
});

void test("parseSubStreamsInfo uses defaults when no entries declared", () => {
  const ctx = makeCtx([0x00]); // terminator
  const info = parseSubStreamsInfo(ctx, 2);
  assert.deepEqual(info.numUnpackStreams, [1, 1]);
  assert.equal(ctx.issues.length, 0);
});

void test("parseStreamsInfo wires pack, unpack and substreams sections", () => {
  // StreamsInfo:
  // 0x06 PackInfo (packPos=0, numPackStreams=1, size=5, end)
  // 0x07 UnpackInfo (folderId=0x0b, folderCount=1, external=0, coderCount=1, flags=0x01, methodId=0x21, sizesId=0x0c, size=5, crc/end marker=0x00)
  // 0x08 SubStreamsInfo (end marker)
  // 0x00 end StreamsInfo
  const bytes = [
    0x06, 0x00, 0x01, 0x09, 0x05, 0x00,
    0x07, 0x0b, 0x01, 0x00, 0x01, 0x01, 0x21, 0x0c, 0x05, 0x00,
    0x08, 0x00,
    0x00
  ];
  const ctx = makeCtx(bytes);
  const info = parseStreamsInfo(ctx);
  assert.equal(info.packInfo?.packSizes[0], 5n);
  assert.equal(info.unpackInfo?.folders.length, 1);
  assert.deepEqual(info.subStreamsInfo?.numUnpackStreams, [1]);
  assert.equal(ctx.issues.length, 0);
});
