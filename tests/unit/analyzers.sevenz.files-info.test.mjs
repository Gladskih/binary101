"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFilesInfo } from "../../dist/analyzers/sevenz/files-info.js";

const encodeUint64 = value => {
  if (value < 0 || value > 0x7f) throw new Error("encodeUint64 helper only supports small values");
  return [value];
};

const makeCtx = bytes => ({
  dv: new DataView(Uint8Array.from(bytes).buffer),
  offset: 0,
  issues: []
});

test("parseFilesInfo reads names and defaults remaining flags", () => {
  const namesBuffer = Buffer.from("foo\u0000bar\u0000", "utf16le");
  const namesSize = 1 + namesBuffer.length; // external flag + names bytes
  const bytes = [
    ...encodeUint64(2), // fileCount
    0x11, // Names property
    ...encodeUint64(namesSize),
    0x00, // external flag
    ...namesBuffer,
    0x00 // terminator
  ];
  const ctx = makeCtx(bytes);
  const info = parseFilesInfo(ctx);
  assert.equal(info.fileCount, 2);
  assert.deepEqual(
    info.files.map(file => file.name),
    ["foo", "bar"]
  );
  assert.equal(info.hasNames, true);
  assert.equal(info.hasModificationTimes, false);
  info.files.forEach(file => {
    assert.equal(file.hasStream, true);
    assert.equal(Boolean(file.isDirectory), false);
  });
  assert.equal(ctx.issues.length, 0);
});
