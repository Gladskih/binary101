"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseAni } from "../../analyzers/ani/index.js";
import { createAniFile, buildRiffFile } from "../fixtures/riff-sample-files.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("parseAni reads header, rates, and sequence", async () => {
  const ani = expectDefined(await parseAni(createAniFile()));
  assert.strictEqual(ani.header?.frameCount, 2);
  assert.strictEqual(ani.frames, 2);
  assert.strictEqual(ani.rates.length, 2);
  assert.strictEqual(ani.sequence.length, 2);
  assert.ok(ani.header?.defaultFps && ani.header.defaultFps > 0);
  assert.ok(ani.infoTags.length >= 1);
});

void test("parseAni returns null for non-ANI form types", async () => {
  const riff = buildRiffFile("TEST", [], "test.riff", "application/octet-stream");
  const ani = await parseAni(riff);
  assert.strictEqual(ani, null);
});
