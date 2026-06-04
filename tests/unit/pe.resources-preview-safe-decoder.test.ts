"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  runAsyncPreviewDecoder,
  runSyncPreviewDecoder
} from "../../analyzers/pe/resources/preview/safe-preview-decoder.js";
import type { ResourcePreviewResult } from "../../analyzers/pe/resources/preview/types.js";

void test("runSyncPreviewDecoder returns results and converts thrown errors to issues", () => {
  const preview: ResourcePreviewResult = { issues: ["fixture issue"] };

  assert.equal(runSyncPreviewDecoder(() => preview), preview);
  assert.deepEqual(runSyncPreviewDecoder(() => {
    throw new Error("fixture failure");
  }), { issues: ["Preview failed: fixture failure"] });
});

void test(
  "runAsyncPreviewDecoder returns results and converts rejected errors to issues",
  async () => {
    const preview: ResourcePreviewResult = { issues: ["fixture issue"] };

    assert.equal(await runAsyncPreviewDecoder(async () => preview), preview);
    assert.deepEqual(await runAsyncPreviewDecoder(async () => {
      throw new Error("fixture failure");
    }), { issues: ["Preview failed: fixture failure"] });
  }
);
