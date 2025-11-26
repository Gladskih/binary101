import assert from "node:assert/strict";
import { test } from "node:test";

import {
  escapeHtml,
  renderDefinitionRow,
  renderFlagChips,
  renderOptionChips,
  safe
} from "../../html-utils.js";

void test("escapeHtml replaces risky characters while leaving safe ones alone", () => {
  const raw = `5 < 6 && "quote"`;
  const escaped = escapeHtml(raw);
  assert.strictEqual(escaped, "5 &lt; 6 && &quot;quote&quot;");
  assert.strictEqual(safe(raw), escaped);
});

void test("renderDefinitionRow emits tooltip-escaped definition pairs", () => {
  const html = renderDefinitionRow("Label", "<b>value</b>", 'tooltip with <tag> and "quotes"');
  assert.ok(html.startsWith("<dt"));
  assert.ok(html.includes('title="tooltip with &lt;tag> and &quot;quotes&quot;"'));
  assert.ok(html.endsWith("</dd>"));
});

void test("renderDefinitionRow omits title attribute when tooltip is missing", () => {
  const html = renderDefinitionRow("Plain", "<i>value</i>");
  assert.ok(html.startsWith("<dt"));
  assert.ok(!html.includes('title="'));
});

void test("renderOptionChips marks the selected option and formats tooltips", () => {
  const html = renderOptionChips(0x02, [
    [0x01, "One"],
    [0x02, "Two"]
  ]);

  assert.ok(html.includes('class="opt dim" title="One (0x0001)"'));
  assert.ok(html.includes('class="opt sel" title="Two (0x0002)"'));
});

void test("renderFlagChips marks set bits, dims others, and escapes labels", () => {
  const html = renderFlagChips(0x01, [
    [0x01, "READ", "<allowed>"],
    [0x02, "WRITE", "write access"]
  ]);

  assert.ok(html.includes('class="opt sel" title="READ - &lt;allowed> (0x0001)"'));
  assert.ok(html.includes('class="opt dim" title="WRITE - write access (0x0002)"'));
});

void test("escapeHtml handles non-string inputs", () => {
  const htmlNumber = escapeHtml(42);
  const htmlNull = escapeHtml(null);
  assert.strictEqual(htmlNumber, "42");
  assert.strictEqual(htmlNull, "null");
});