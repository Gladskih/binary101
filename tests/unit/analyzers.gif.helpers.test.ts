"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  bytesToAscii,
  parseApplicationExtension,
  parseCommentExtension,
  parseGraphicControl,
  parsePlainTextExtension,
  readAsciiRange,
  readSubBlocks
} from "../../dist/analyzers/gif/helpers.js";

const makeDv = bytes => new DataView(Uint8Array.from(bytes).buffer);

test("readAsciiRange and bytesToAscii stop at NUL", () => {
  const dv = makeDv([0x41, 0x42, 0x00, 0x43]);
  assert.equal(readAsciiRange(dv, 0, 4), "AB");
  assert.equal(bytesToAscii([0x44, 0x45, 0x00, 0x46]), "DE");
});

test("readSubBlocks aggregates sizes and truncation", () => {
  const dv = makeDv([0x03, 1, 2, 3, 0x02, 4, 5, 0x00]);
  const res = readSubBlocks(dv, 0, 4);
  assert.equal(res.totalSize, 5);
  assert.equal(res.blockCount, 2);
  assert.deepEqual(res.previewBytes, [1, 2, 3, 4]);
});

test("readSubBlocks notes truncation on premature end", () => {
  const dv = makeDv([0x04, 1, 2]);
  const res = readSubBlocks(dv, 0, 2);
  assert.equal(res.truncated, true);
  assert.equal(res.totalSize, 2);
});

test("parseGraphicControl handles valid and missing terminator", () => {
  // valid GCE: 0x21, 0xf9, blockSize=4, packed=0x05 (disposal=1), delay=2, transIndex=7, terminator=0
  const bytes = [0x21, 0xf9, 4, 0x05, 0x02, 0x00, 0x07, 0x00];
  const dv = makeDv(bytes);
  const { gce, warning } = parseGraphicControl(dv, 0);
  assert.equal(warning, null);
  assert.equal(gce.disposalMethod, "Keep previous frame (do not dispose)");
  assert.equal(gce.delayMs, 20);
  assert.equal(gce.transparentColorIndex, 7);

  const missingTerminator = parseGraphicControl(makeDv([0x21, 0xf9, 4, 0x00, 0, 0, 0, 0x99]), 0);
  assert.ok(missingTerminator.warning?.includes("missing terminator"));
});

test("parseApplicationExtension parses loop count and warns on size", () => {
  // blockSize 11, identifier 'NETSCAPE', auth '2.0', subblock [1, 0x01, 0x00] loop count =1, terminator=0
  const header = [
    0x21, 0xff, 0x0b,
    ..."NETSCAPE".split("").map(ch => ch.charCodeAt(0)),
    ..."2.0".split("").map(ch => ch.charCodeAt(0)),
    0x03, 0x01, 0x01, 0x00, 0x00
  ];
  const dv = makeDv(header);
  const { info, warning } = parseApplicationExtension(dv, 0);
  assert.equal(warning, null);
  assert.equal(info.identifier, "NETSCAPE");
  assert.equal(info.authCode, "2.0");
  assert.equal(info.loopCount, 1);

  const badSize = parseApplicationExtension(
    makeDv([0x21, 0xff, 0x05, ...new Array(11).fill(0)]),
    0
  );
  assert.ok(badSize.warning?.includes("invalid block size"));
});

test("parseCommentExtension decodes text and reports truncation", () => {
  const dv = makeDv([0x21, 0xfe, 0x03, ..."Hi!".split("").map(ch => ch.charCodeAt(0)), 0x00]);
  const { comment } = parseCommentExtension(dv, 0);
  assert.equal(comment.text, "Hi!");
  assert.equal(comment.truncated, false);
});

test("parsePlainTextExtension notes truncated or complete blocks", () => {
  const truncated = parsePlainTextExtension(makeDv([0x21]), 0);
  assert.ok(truncated.warning);

  const dv = makeDv([0x21, 0x01, 0x0c, ...new Array(12).fill(0), 0x00]);
  const complete = parsePlainTextExtension(dv, 0);
  assert.equal(complete.warning, null);
});
