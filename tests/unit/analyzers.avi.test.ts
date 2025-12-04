"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseAvi } from "../../analyzers/avi/index.js";
import { buildRiffFile, createAviFile } from "../fixtures/riff-sample-files.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("parseAvi extracts header and stream info", async () => {
  const avi = expectDefined(await parseAvi(createAviFile()));
  assert.strictEqual(avi.mainHeader?.width, 320);
  assert.strictEqual(avi.mainHeader?.height, 240);
  assert.ok(avi.mainHeader?.frameRate && avi.mainHeader.frameRate > 0);
  assert.strictEqual(avi.streams.length, 1);
  const stream = expectDefined(avi.streams[0]);
  assert.strictEqual(stream.header?.type, "vids");
  assert.strictEqual(stream.header?.length, 10);
  assert.ok(stream.format && "width" in stream.format);
});

void test("parseAvi reports missing avih chunk", async () => {
  const aviFile = buildRiffFile("AVI ", [], "empty.avi", "video/x-msvideo");
  const avi = expectDefined(await parseAvi(aviFile));
  assert.ok(avi.issues.some(issue => issue.toLowerCase().includes("missing avih")));
});
