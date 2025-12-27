"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseTga } from "../../analyzers/tga/index.js";
import { renderTga } from "../../renderers/tga/index.js";
import { createTgaFile } from "../fixtures/image-sample-files.js";
import {
  createTgaColorMappedFile,
  createTgaV2WithExtensionAndDeveloperArea,
  createTgaWithBinaryImageId
} from "../fixtures/tga-fixtures.js";
import { MockFile } from "../helpers/mock-file.js";

void test("renderTga renders core header fields", async () => {
  const parsed = await parseTga(createTgaFile());
  assert.ok(parsed);
  const html = renderTga(parsed);
  assert.match(html, /TGA structure/i);
  assert.match(html, /Image type/i);
  assert.match(html, /Dimensions/i);
  assert.match(html, /Pixel depth/i);
  assert.match(html, /optionsRow/);
});

void test("renderTga renders extension and developer sections for v2.0 files", async () => {
  const parsed = await parseTga(createTgaV2WithExtensionAndDeveloperArea());
  assert.ok(parsed);
  const html = renderTga(parsed);
  assert.match(html, /Extension area/i);
  assert.match(html, /Developer directory/i);
  assert.match(html, /TRUEVISION-XFILE/i);
});

void test("renderTga renders palette summaries for color-mapped images", async () => {
  const parsed = await parseTga(createTgaColorMappedFile());
  assert.ok(parsed);
  const html = renderTga(parsed);
  assert.match(html, /Color map data/i);
  assert.match(html, /entries/i);
});

void test("renderTga renders binary Image IDs as hex previews", async () => {
  const parsed = await parseTga(createTgaWithBinaryImageId());
  assert.ok(parsed);
  const html = renderTga(parsed);
  assert.match(html, /0x/i);
});

void test("renderTga tolerates truncated headers", async () => {
  const file = new MockFile(new Uint8Array([0x00, 0x00]), "truncated.tga", "application/octet-stream");
  const parsed = await parseTga(file);
  assert.ok(parsed);
  assert.match(renderTga(parsed), /Unknown/i);
});
