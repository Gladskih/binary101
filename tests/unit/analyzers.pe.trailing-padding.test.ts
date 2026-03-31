"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe } from "../../analyzers/pe/index.js";
import { MockFile } from "../helpers/mock-file.js";
import { createPeWithSectionAndIat } from "../fixtures/sample-files-pe.js";

void test("parsePe classifies trailing zero bytes that exactly finish FileAlignment as explicit padding", async () => {
  const base = createPeWithSectionAndIat();
  const overlayPayloadSize = 0x35;
  const fileSize = 0x600;
  const bytes = new Uint8Array(fileSize);
  bytes.set(base.subarray(0, 0x400));
  bytes.fill(0x41, 0x400, 0x400 + overlayPayloadSize);
  const file = new MockFile(bytes, "aligned-padding.exe", "application/vnd.microsoft.portable-executable");

  const parsed = await parsePe(file);
  if (!parsed) assert.fail("expected PE parse result");

  assert.equal(parsed.overlaySize, 0x200);
  assert.equal(parsed.trailingAlignmentPaddingSize, 0x1cb);
});
