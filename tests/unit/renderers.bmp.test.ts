"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseBmp } from "../../analyzers/bmp/index.js";
import { renderBmp } from "../../renderers/bmp/index.js";
import {
  createBmp16BitBitfieldsFile,
  createBmp8BitPaletteFile,
  createBmpFile,
  createBmpV5SrgbFile,
  createTruncatedBmpFile
} from "../fixtures/bmp-fixtures.js";

void test("renderBmp renders core BMP structure fields", async () => {
  const bmp = await parseBmp(createBmpFile());
  assert.ok(bmp);
  const html = renderBmp(bmp);
  assert.match(html, /BMP structure/i);
  assert.match(html, /Dimensions/i);
  assert.match(html, /Pixel array/i);
});

void test("renderBmp renders palette summary for indexed BMPs", async () => {
  const bmp = await parseBmp(createBmp8BitPaletteFile());
  assert.ok(bmp);
  const html = renderBmp(bmp);
  assert.match(html, /Palette/i);
  assert.match(html, /4 entries/i);
});

void test("renderBmp renders BITFIELDS masks", async () => {
  const bmp = await parseBmp(createBmp16BitBitfieldsFile());
  assert.ok(bmp);
  const html = renderBmp(bmp);
  assert.match(html, /Masks/i);
  assert.match(html, /0x0000f800/i);
});

void test("renderBmp renders warnings for truncated inputs", async () => {
  const bmp = await parseBmp(createTruncatedBmpFile());
  assert.ok(bmp);
  const html = renderBmp(bmp);
  assert.match(html, /Warnings/i);
  assert.match(html, /truncated/i);
});

void test("renderBmp renders option chips for enumerated BMP fields", async () => {
  const bmp = await parseBmp(createBmpV5SrgbFile());
  assert.ok(bmp);
  const html = renderBmp(bmp);
  assert.match(html, /optionsRow/);
});
