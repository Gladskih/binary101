import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeElfInstructionSets } from "../../../../analyzers/elf/disassembly-analyze.js";
import { decodeElfSymbolNames } from "../../../../analyzers/elf/symbol-names.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";
import { elfIsaDataOptions, isaDataBytes } from "../../../fixtures/isa-known-data.js";

for (const machine of [3, 62, 183]) {
  void test(`ELF machine ${machine} excludes demangled data from fallthrough and pointer seeds`, async () => {
    const file = new File([isaDataBytes(machine)], "isa-data.elf");
    const opts = elfIsaDataOptions(machine);
    const elf = { ...relocationFixture().elf, symbolTables: opts.symbolTables! };
    await decodeElfSymbolNames(elf);

    const report = await analyzeElfInstructionSets(file, opts);

    assert.equal(report.bytesDecoded, 8);
    assert.equal(report.instructionCount, machine === 183 ? 2 : 8);
    assert.equal(report.invalidInstructionCount, 0);
    assert.ok(!report.instructionSets.some(set => /AVX|SVE|SME/.test(set.label)));
    assert.ok(report.issues.some(issue => /known data/.test(issue)));
    assert.equal(report.seedSummary?.sources.find(source =>
      source.source.includes("init_array"))?.skippedData, 1);
  });

  void test(`ELF machine ${machine} refuses an entrypoint in the middle of a sized data symbol`, async () => {
    const file = new File([isaDataBytes(machine)], "isa-data.elf");
    const opts = elfIsaDataOptions(machine);
    opts.symbolTables![0]!.entries[0]!.info = 0x11; // STT_OBJECT, independent of mangling.
    opts.entrypointVaddr = 0x100cn;

    const report = await analyzeElfInstructionSets(file, opts);

    assert.equal(report.bytesDecoded, 8);
    assert.equal(report.seedSummary?.sources[0]?.skippedData, 1);
    assert.ok(report.issues.some(issue => /Skipped known-data seed/.test(issue)));
  });
}

void test("a decoder must not count an instruction overlapping a data interval", async () => {
  const opts = elfIsaDataOptions(62);
  const bytes = isaDataBytes(62);
  bytes.set([0xb8, 0, 0, 0, 0]); // MOV eax,imm32 occupies five bytes.
  opts.symbolTables![0]!.entries[0]!.info = 0x11;
  opts.symbolTables![0]!.entries[0]!.value = 0x1002n;
  opts.sections.pop();

  const report = await analyzeElfInstructionSets(new File([bytes], "overlap.elf"), opts);

  assert.equal(report.instructionCount, 0);
  assert.equal(report.bytesDecoded, 0);
  assert.equal(report.invalidInstructionCount, 0);
});

void test("a defined dynamic NOTYPE symbol uses its successful Itanium AST for data evidence", async () => {
  const opts = elfIsaDataOptions(62);
  delete opts.symbolTables;
  opts.dynSymbols = { total: 2, issues: [], importSymbols: [], exportSymbols: [{
    index: 1, name: "_Z5value", value: 0x1008n, size: 8n, bind: 1, bindName: "GLOBAL",
    type: 0, typeName: "NOTYPE", visibility: 0, visibilityName: "DEFAULT", shndx: 1
  }] };
  await decodeElfSymbolNames({ ...relocationFixture().elf, dynSymbols: opts.dynSymbols });

  const report = await analyzeElfInstructionSets(new File([isaDataBytes(62)], "dynamic-data.so"), opts);

  assert.equal(report.bytesDecoded, 8);
  assert.ok(!report.instructionSets.some(set => set.id === "AVX"));
});

for (const machine of [3, 62, 183]) {
  void test(`ELF machine ${machine} stops a direct branch into a data object's interior`, async () => {
    const bytes = isaDataBytes(machine);
    if (machine === 183) new DataView(bytes.buffer).setUint32(0, 0x14000003, true);
    else bytes.set([0xeb, 10]); // Intel SDM JMP rel8: next IP 2 + 10 = 12.
    const opts = elfIsaDataOptions(machine);
    opts.symbolTables![0]!.entries[0]!.info = 0x11;

    const report = await analyzeElfInstructionSets(new File([bytes], "branch-data.elf"), opts);

    assert.equal(report.instructionCount, 1);
    assert.equal(report.bytesDecoded, machine === 183 ? 4 : 2);
    assert.ok(report.issues.some(issue => /known data/.test(issue)));
  });
}
