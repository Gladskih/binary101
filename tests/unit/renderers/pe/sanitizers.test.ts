import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPeSanitizers } from "../../../../renderers/pe/sanitizers.js";
import { getPeLazySectionDescriptors } from "../../../../renderers/pe/lazy-section-shells.js";
import { sanitizerPe, sanitizerImport } from "../../../fixtures/sanitizer-metadata.js";

void test("renders PE sanitizer dependencies and references", () => {
  const pe = sanitizerPe();
  pe.imports.entries = [sanitizerImport("clang_rt.asan_dynamic-x86_64.dll",
    ["__asan_init", "__asan_report_load4"])];
  assert.match(renderPeSanitizers(pe), /Runtime dependency/);
  assert.match(renderPeSanitizers(pe), /__asan_report_load4/);
  assert.ok(getPeLazySectionDescriptors(pe).some(section => section.key === "sanitizers"));
});

void test("shows inconclusive absence for a plain PE", () => {
  assert.match(renderPeSanitizers(sanitizerPe()), /No supported sanitizer evidence/);
});
