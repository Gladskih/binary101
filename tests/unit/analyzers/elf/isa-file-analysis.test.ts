import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { analyzeElfInstructionSets } from "../../../../analyzers/elf/disassembly-analyze.js";
import { createElfIsaDataFile } from "../../../fixtures/elf-isa-data-file.js";

void test("complete sectionless ELF parsing supplies data evidence to ISA analysis", async () => {
  const file = new File([createElfIsaDataFile()], "isa-data.so");
  const elf = await parseElf(file);
  assert.ok(elf);

  const report = await analyzeElfInstructionSets(file, { machine: elf.header.machine,
    fileType: elf.header.type, is64Bit: elf.is64, littleEndian: elf.littleEndian,
    entrypointVaddr: elf.header.entry, programHeaders: elf.programHeaders, sections: elf.sections,
    ...(elf.dynSymbols ? { dynSymbols: elf.dynSymbols } : {}) });

  assert.equal(report.bytesDecoded, 8);
  assert.equal(report.instructionCount, 8);
  assert.equal(report.seedSummary?.sources.find(source => source.source === "DT_INIT")?.skippedData, 1);
  assert.ok(!report.instructionSets.some(set => set.id === "AVX"));
});
