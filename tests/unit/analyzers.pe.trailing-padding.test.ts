"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe } from "../../analyzers/pe/index.js";
import { MockFile } from "../helpers/mock-file.js";
import { createPeWithSectionAndIatFixture } from "../fixtures/sample-files-pe.js";

void test("parsePe classifies trailing zero bytes that exactly finish FileAlignment as explicit padding", async () => {
  const fixture = createPeWithSectionAndIatFixture();
  // Fill exactly half of the trailing FileAlignment block so the remaining half is explicit zero padding.
  const overlayPayloadSize = fixture.fileAlignment / 2;
  const fileSize = fixture.rawImageEnd + fixture.fileAlignment;
  const bytes = new Uint8Array(fileSize);
  bytes.set(fixture.bytes.subarray(0, fixture.rawImageEnd));
  bytes.fill(1, fixture.rawImageEnd, fixture.rawImageEnd + overlayPayloadSize);
  const file = new MockFile(bytes);

  const parsed = await parsePe(file);
  if (!parsed) assert.fail("expected PE parse result");

  assert.equal(parsed.overlaySize, fixture.fileAlignment);
  assert.equal(parsed.trailingAlignmentPaddingSize, fixture.fileAlignment - overlayPayloadSize);
});
