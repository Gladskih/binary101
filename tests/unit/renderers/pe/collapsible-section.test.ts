"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPeSectionStart } from "../../../../renderers/pe/collapsible-section.js";

void test("renderPeSectionStart inserts known PE section descriptions inside the fold", () => {
  const html = renderPeSectionStart("Load Config", "v1.2");

  assert.ok(html.includes("<b>Load Config</b> - v1.2"));
  assert.ok(html.includes("PE loader metadata for compiler and OS hardening features"));
});

void test("renderPeSectionStart leaves unknown section titles without guessed descriptions", () => {
  const html = renderPeSectionStart("Unit Test Only");

  assert.ok(!html.includes("smallNote"));
});
