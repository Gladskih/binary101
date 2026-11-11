import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElfSanitizers } from "../../../../renderers/elf/sanitizers.js";
import { getElfLazySections, renderElfLazy } from "../../../../renderers/elf/lazy-sections.js";
import { analyzeElfSanitizers } from "../../../../analyzers/elf/sanitizers.js";
import { sanitizerElf, sanitizerDynamicSymbol } from "../../../fixtures/sanitizer-metadata.js";

void test("renders the same sanitizer table eagerly and through the lazy ELF section", () => {
  const elf = sanitizerElf();
  elf.dynSymbols = { total: 2, issues: [], exportSymbols: [], importSymbols:
    ["__asan_init", "__asan_report_load4"].map(sanitizerDynamicSymbol) };
  elf.sanitizerEvidence = analyzeElfSanitizers(elf);
  const out: string[] = [];
  renderElfSanitizers(elf, out);
  assert.match(out.join(""), /Sanitizer evidence/);
  assert.match(out.join(""), /__asan_report_load4/);
  const lazy = getElfLazySections(elf).find(section => section.key === "sanitizers");
  assert.ok(lazy);
  assert.match(lazy.render(), /__asan_report_load4/);
});

void test("does not inspect symbol names while creating lazy shells", () => {
  const elf = sanitizerElf();
  elf.dynSymbols = { total: 0, issues: [], importSymbols: [], exportSymbols: [] };
  Object.defineProperty(elf.dynSymbols, "importSymbols", {
    get: () => { throw new Error("eager sanitizer scan"); }
  });
  assert.equal(getElfLazySections(elf).find(section => section.key === "sanitizers"), undefined);
  assert.doesNotMatch(renderElfLazy(elf), /Checks without findings/);
});

void test("lists an ELF sanitizer check with no evidence in the common section", () => {
  const elf = sanitizerElf();
  elf.sanitizerEvidence = [];
  const html = renderElfLazy(elf);
  assert.match(html, /Checks without findings/);
  assert.match(html, /<dt>Sanitizer evidence<\/dt>/);
  assert.doesNotMatch(html, /data-elf-lazy-section="sanitizers"/);
  assert.doesNotMatch(html, /<dt>Qt \/ GLib embedded resources<\/dt>/);
});
