"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { formatElfHex, formatElfList, formatElfMaybeHumanSize } from "../../renderers/elf/value-format.js";

void test("formatElfHex formats bigints and numbers", () => {
  assert.equal(formatElfHex(0x1234n), "0x1234");
  assert.equal(formatElfHex(0x1234n, 8), "0x00001234");
  assert.equal(formatElfHex(0x1234, 8), "0x00001234");
});

void test("formatElfList escapes and joins strings", () => {
  const html = formatElfList(["a", "\"b\"", "<c>"]);
  assert.ok(html.includes("a"));
  assert.ok(html.includes("&quot;b&quot;"));
  assert.ok(html.includes("&lt;c>"));
});

void test("formatElfMaybeHumanSize shows human sizes when safe", () => {
  const html = formatElfMaybeHumanSize(4096n);
  assert.ok(html.includes("4 KB"));
  assert.ok(html.includes("0x1000"));
});

