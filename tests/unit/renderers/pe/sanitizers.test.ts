import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPeSanitizers } from "../../../../renderers/pe/sanitizers.js";
import { analyzePeSanitizers } from "../../../../analyzers/pe/sanitizers.js";
import { renderPe } from "../../../../renderers/pe/index.js";
import { getPeLazySectionDescriptors } from "../../../../renderers/pe/lazy-section-shells.js";
import { sanitizerPe, sanitizerImport } from "../../../fixtures/sanitizer-metadata.js";

void test("renders PE sanitizer dependencies and references", () => {
  const pe = sanitizerPe();
  pe.imports.entries = [sanitizerImport("clang_rt.asan_dynamic-x86_64.dll",
    ["__asan_init", "__asan_report_load4"])];
  pe.sanitizerEvidence = analyzePeSanitizers(pe);
  assert.match(renderPeSanitizers(pe), /Runtime dependency/);
  assert.match(renderPeSanitizers(pe), /__asan_report_load4/);
  assert.ok(getPeLazySectionDescriptors(pe).some(section => section.key === "sanitizers"));
});

void test("lists completed PE checks with no evidence together", () => {
  const pe = sanitizerPe();
  pe.sanitizerEvidence = [];
  pe.embeddedResources = null;
  pe.packers = null;
  const html = renderPe(pe);
  assert.match(html, /Checks without findings/);
  assert.match(html, /<dt>Sanitizer evidence<\/dt>/);
  assert.match(html, /<dt>Qt \/ GLib embedded resources<\/dt>/);
  assert.match(html, /<dt>PE packagers<\/dt>/);
  assert.doesNotMatch(html, /data-pe-lazy-section="sanitizers"/);
  assert.doesNotMatch(html, /<dt>ReadyToRun<\/dt>/);
});
