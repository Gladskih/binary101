"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseBmp } from "../../analyzers/bmp/index.js";
import { renderBmpColorSpace } from "../../renderers/bmp/color-space.js";
import {
  createBmpFile,
  createBmpV5EmbeddedProfileFile,
  createBmpV5LinkedProfileFile,
  createBmpV5SrgbFile
} from "../fixtures/bmp-fixtures.js";

void test("renderBmpColorSpace returns empty string when no color space metadata is present", async () => {
  const bmp = await parseBmp(createBmpFile());
  assert.ok(bmp);
  assert.strictEqual(renderBmpColorSpace(bmp), "");
});

void test("renderBmpColorSpace renders CSType and intent chips for BITMAPV5HEADER", async () => {
  const bmp = await parseBmp(createBmpV5SrgbFile());
  assert.ok(bmp);
  const html = renderBmpColorSpace(bmp);
  assert.match(html, /Color space/i);
  assert.match(html, /CSType/);
  assert.match(html, /optionsRow/);
  assert.match(html, /LCS_sRGB/i);
});

void test("renderBmpColorSpace renders linked profile file name", async () => {
  const bmp = await parseBmp(createBmpV5LinkedProfileFile());
  assert.ok(bmp);
  const html = renderBmpColorSpace(bmp);
  assert.match(html, /Profile/i);
  assert.match(html, /sRGB\.icc/);
});

void test("renderBmpColorSpace renders embedded profile signature", async () => {
  const bmp = await parseBmp(createBmpV5EmbeddedProfileFile());
  assert.ok(bmp);
  const html = renderBmpColorSpace(bmp);
  assert.match(html, /Profile signature/i);
  assert.match(html, /acsp/i);
});
