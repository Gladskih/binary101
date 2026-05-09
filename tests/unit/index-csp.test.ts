"use strict";

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const indexHtml = readFileSync("index.html", "utf8");

void test("index CSP permits local data URL font previews", () => {
  assert.match(indexHtml, /font-src\s+'self'\s+data:/);
});
