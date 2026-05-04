"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDosHeader } from "../../renderers/pe/dos-header.js";
import { createBasePe } from "../fixtures/pe-renderer-headers-fixture.js";

void test("renderDosHeader shows field hints inline instead of tooltip-only text", () => {
  const pe = createBasePe();
  const out: string[] = [];
  renderDosHeader(pe, out);
  const html = out.join("");
  assert.match(html, /<th>Field<\/th><th>Value<\/th><th>Meaning<\/th>/);
  assert.match(html, /<tr><th scope="row">e_magic<\/th><td>MZ<\/td><td class="smallNote"[^>]*>/);
  assert.match(html, /<td class="smallNote"[^>]*>DOS header signature\./);
  assert.doesNotMatch(html, /<dt title="DOS header signature\./);
  assert.doesNotMatch(html, /<dl>/);
});

void test("renderDosHeader escapes DOS stub strings", () => {
  const pe = createBasePe();
  pe.dos.stub = { kind: "stub", note: "<note>", strings: ["<stub text>"] };
  const out: string[] = [];
  renderDosHeader(pe, out);
  const html = out.join("");
  assert.ok(html.includes("DOS stub: stub - &lt;note>"));
  assert.ok(html.includes("&lt;stub text>"));
  assert.doesNotMatch(html, /<stub text>/);
});
