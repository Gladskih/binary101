"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPeDiagnostics } from "../../renderers/pe/diagnostics.js";

void test("renderPeDiagnostics wraps even a single warning in details", () => {
  const html = renderPeDiagnostics("Resource warnings", [
    "Top-level resource type entry TYPE_1325421056 points directly to data."
  ]);

  assert.match(html, /<details/);
  assert.match(html, /<summary/);
  assert.match(html, /Resource warnings/);
  assert.match(html, /1 message/);
  assert.match(html, /TYPE_1325421056 points directly to data/);
});

void test("renderPeDiagnostics groups larger warning sets by normalized pattern", () => {
  const html = renderPeDiagnostics("Resource warnings", [
    "Entry 1 at 0x10 is truncated.",
    "Entry 2 at 0x20 is truncated.",
    "Entry 3 at 0x30 is truncated.",
    "Entry 4 at 0x40 is truncated.",
    "Entry 5 at 0x50 is truncated.",
    "Entry 6 at 0x60 is truncated.",
    "Entry 7 at 0x70 is truncated.",
    "Entry 8 at 0x80 is truncated.",
    "Entry 9 at 0x90 is truncated."
  ]);

  assert.match(html, /grouped into 1 pattern/);
  assert.match(html, /0x\.\.\./);
  assert.match(html, /Entry 1 at 0x10 is truncated/);
});

void test("renderPeDiagnostics normalizes TYPE_<number> resource warnings into one pattern", () => {
  const html = renderPeDiagnostics("Resource warnings", [
    "Top-level resource type entry TYPE_336794387 points directly to data; type entries should point to second-level subdirectories.",
    "Top-level resource type entry TYPE_303239957 points directly to data; type entries should point to second-level subdirectories.",
    "Top-level resource type entry TYPE_1993274876 points directly to data; type entries should point to second-level subdirectories.",
    "Top-level resource type entry TYPE_1 points directly to data; type entries should point to second-level subdirectories.",
    "Top-level resource type entry TYPE_2 points directly to data; type entries should point to second-level subdirectories.",
    "Top-level resource type entry TYPE_3 points directly to data; type entries should point to second-level subdirectories.",
    "Top-level resource type entry TYPE_4 points directly to data; type entries should point to second-level subdirectories.",
    "Top-level resource type entry TYPE_5 points directly to data; type entries should point to second-level subdirectories.",
    "Top-level resource type entry TYPE_6 points directly to data; type entries should point to second-level subdirectories."
  ]);

  assert.match(html, /grouped into 1 pattern/);
  assert.match(html, /TYPE_#/);
});
