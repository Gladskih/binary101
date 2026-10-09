"use strict";

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const indexHtml = readFileSync("index.html", "utf8");

void test("index CSP permits local data URL font previews", () => {
  assert.match(indexHtml, /font-src\s+'self'\s+data:/);
});

void test("index CSP restricts fetch connections to the application and local development sockets", () => {
  assert.match(indexHtml, /connect-src 'self' ws:\/\/127\.0\.0\.1:\* ws:\/\/localhost:\*;/);
});
