"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addBitmapPreview } from "../../analyzers/pe/resources-preview-bitmap.js";
import { createBmpFile } from "../fixtures/image-sample-files.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("addBitmapPreview wraps DIB bytes into an inline BMP preview", () => {
  const bitmapResource = createBmpFile().data.subarray(14);
  const result = addBitmapPreview(bitmapResource, "BITMAP");

  assert.strictEqual(result?.preview?.previewKind, "image");
  assert.strictEqual(result?.preview?.previewMime, "image/bmp");
  assert.match(expectDefined(result?.preview?.previewDataUrl), /^data:image\/bmp;base64,/);
});

void test("addBitmapPreview records an issue for malformed DIB headers", () => {
  const result = addBitmapPreview(new Uint8Array([1, 2, 3, 4]), "BITMAP");

  assert.ok((result?.issues || []).some(issue => /BITMAP resource/i.test(issue)));
});
