import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElfSanitizers } from "../../../../renderers/elf/sanitizers.js";
import { getElfLazySections } from "../../../../renderers/elf/lazy-sections.js";
import { sanitizerElf, sanitizerDynamicSymbol } from "../../../fixtures/sanitizer-metadata.js";

void test("renders the same sanitizer table eagerly and through the lazy ELF section", () => {
  const elf = sanitizerElf();
  elf.dynSymbols = { total: 2, issues: [], exportSymbols: [], importSymbols:
    ["__asan_init", "__asan_report_load4"].map(sanitizerDynamicSymbol) };
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
  assert.ok(getElfLazySections(elf).find(section => section.key === "sanitizers"));
});
