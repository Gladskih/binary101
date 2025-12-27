"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { renderTgaDeveloperDirectory } from "../../renderers/tga/developer-directory.js";
import type { TgaDeveloperDirectory } from "../../analyzers/tga/types.js";

void test("renderTgaDeveloperDirectory renders empty tables", () => {
  const dev: TgaDeveloperDirectory = { offset: 200, tagCount: 0, tags: [], truncated: false };
  const html = renderTgaDeveloperDirectory(dev);
  assert.match(html, /Developer directory/i);
  assert.match(html, /No tags/i);
});

void test("renderTgaDeveloperDirectory renders tag rows", () => {
  const dev: TgaDeveloperDirectory = {
    offset: 200,
    tagCount: 1,
    tags: [{ tagNumber: 42, dataOffset: 300, dataSize: 8, truncated: true }],
    truncated: false
  };
  const html = renderTgaDeveloperDirectory(dev);
  assert.match(html, /Tag/);
  assert.match(html, /42/);
  assert.match(html, /Truncated/i);
});

