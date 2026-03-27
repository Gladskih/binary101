"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addAniCursorPreview, addAniIconPreview } from "../../analyzers/pe/resources/preview/ani.js";
import { createAniFile } from "../fixtures/riff-sample-files.js";

void test("ANI standard resource decoders expose animated cursor and icon summaries", async () => {
  const cursorPreview = await addAniCursorPreview(createAniFile().data, "ANICURSOR");
  const iconPreview = await addAniIconPreview(createAniFile().data, "ANIICON");

  assert.strictEqual(cursorPreview?.preview?.previewKind, "summary");
  assert.strictEqual(iconPreview?.preview?.previewKind, "summary");
  assert.ok((cursorPreview?.preview?.previewFields || []).some(field => field.value === "Animated cursor (ANI)"));
  assert.ok((iconPreview?.preview?.previewFields || []).some(field => field.value === "Animated icon (ANI)"));
});
