"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  renderBoundImports,
  renderDelayImports
} from "../../renderers/pe/layout.js";

void test("renderBoundImports renders warning-only results", () => {
  const boundImports: Parameters<typeof renderBoundImports>[0] = {
    warning: "bound warning",
    entries: []
  };
  const out: string[] = [];
  renderBoundImports(boundImports, out);
  const html = out.join("");
  assert.ok(html.includes("Bound imports"));
  assert.ok(html.includes("bound warning"));
});

void test("renderDelayImports renders warning-only results", () => {
  const delayImports: Parameters<typeof renderDelayImports>[0] = {
    warning: "delay warning",
    entries: []
  };
  const out: string[] = [];
  renderDelayImports(delayImports, out);
  const html = out.join("");
  assert.ok(html.includes("Delay-load imports"));
  assert.ok(html.includes("delay warning"));
});
