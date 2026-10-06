import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { parsePe, isPeWindowsParseResult } from "../../analyzers/pe/index.js";
import { analyzeElfSanitizers } from "../../analyzers/elf/sanitizers.js";
import { analyzePeSanitizers } from "../../analyzers/pe/sanitizers.js";

// Expectations come from compiler flags, independently of symbol-name matching rules.
for (const [name, expected] of [
  ["gcc-address", "ASan"], ["gcc-thread", "TSan"], ["gcc-undefined", "UBSan"],
  ["gcc-leak", "LSan"], ["clang-address", "ASan"], ["clang-thread", "TSan"],
  ["clang-undefined", "UBSan"], ["clang-leak", "LSan"], ["clang-memory", "MSan"],
  ["clang-dataflow", "DFSan"], ["clang-hwasan.o", "HWASan"],
  ["clang-ubsan-minimal", "UBSan minimal"], ["clang-realtime", "RTSan"],
  ["clang-type", "TySan"], ["clang-coverage.o", "SanitizerCoverage"],
  ["gcc-address-stripped", "ASan"], ["clang-address-stripped", "ASan"],
  ["gcc-plain", null], ["clang-plain", null], ["gcc-trap", null], ["clang-trap", null],
  ["gcc-strings", null]
] as const) {
  void test(`ELF sanitizer evidence matches real compiler settings: ${name}`, async context => {
    const path = `scan-results/sanitizers/${name}`;
    if (!existsSync(path)) return context.skip("Run samples/sanitizers/build-elf.sh first.");
    const bytes = await readFile(path);
    const elf = await parseElf(new File([bytes], name));
    assert.ok(elf);
    const started = performance.now();
    const evidence = analyzeElfSanitizers(elf);
    context.diagnostic(`${bytes.length} bytes; evidence scan ${(performance.now() - started).toFixed(2)} ms`);
    if (expected) assert.ok(evidence.some(row => row.tool === expected),
      JSON.stringify(evidence));
    else assert.deepEqual(evidence, []);
  });
}

for (const [name, expected] of [
  ["clang-address.exe", "ASan"], ["go-race.exe", "Go race detector"],
  ["go-race-stripped.exe", "Go race detector"], ["go-plain.exe", null],
  ["msvc-address.exe", "ASan"], ["msvc-plain.exe", null]
] as const) {
  void test(`PE sanitizer evidence matches real compiler settings: ${name}`, async context => {
    const path = `scan-results/sanitizers/${name}`;
    if (!existsSync(path)) return context.skip("Build the Windows ASan, plain and Go race samples first.");
    const pe = await parsePe(new File([await readFile(path)], name));
    assert.ok(pe && isPeWindowsParseResult(pe));
    const started = performance.now();
    const evidence = analyzePeSanitizers(pe);
    context.diagnostic(`evidence scan ${(performance.now() - started).toFixed(2)} ms`);
    if (expected) assert.ok(evidence.some(row => row.tool === expected), JSON.stringify(evidence));
    else assert.deepEqual(evidence, []);
  });
}

void test("truncated real ELF does not turn diagnostic strings into sanitizer evidence", async context => {
  const path = "scan-results/sanitizers/clang-address";
  if (!existsSync(path)) return context.skip("Build ELF samples first.");
  const bytes = await readFile(path);
  for (const size of [0, 1, 63, 128, Math.floor(bytes.length / 2)]) {
    const elf = await parseElf(new File([bytes.subarray(0, size)], "truncated"));
    if (elf) assert.doesNotThrow(() => analyzeElfSanitizers(elf));
  }
});
