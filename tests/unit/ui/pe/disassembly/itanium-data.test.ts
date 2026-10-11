import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { collectPeDisassemblySeeds } from "../../../../../ui/pe-disassembly-seeds.js";
import { analyzePeInstructionSets } from "../../../../../analyzers/pe/disassembly/analyze.js";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { createPeDataSeedFixture } from "../../../../fixtures/pe-data-seeds.js";

void test("complete PE parsing excludes Itanium data aliases from export and pointer metadata seeds", async () => {
  const { file, targets } = createPeDataSeedFixture([["_Z1fv"], ["_Z5value", "PlainAlias"],
    ["_ZTV1A"], ["_ZThn8_N1A1fEv"], ["PlainC"], [], ["_Zbroken"]]);
  const pe = await parsePe(file);
  assert.ok(pe && isPeWindowsParseResult(pe));

  const seeds = await collectPeDisassemblySeeds(file, pe);
  const report = await analyzePeInstructionSets(createFileRangeReader(file, 0, file.size), {
    ...seeds, coffMachine: seeds.canonicalMachine, is64Bit: true,
    imageBase: pe.opt.ImageBase, sections: pe.sections, rvaToOff: pe.rvaToOff
  });

  assert.deepEqual(seeds.dataRvas, [targets[1], targets[2]]);
  assert.deepEqual(seeds.exportRvas, targets.filter((_target, index) => index !== 1 && index !== 2));
  assert.deepEqual(seeds.extraEntrypoints, [{ source: "MSVC RTTI vftables", rvas: seeds.exportRvas }]);
  assert.equal(report.instructionCount, 5);
  assert.equal(report.bytesDecoded, 5);
  assert.deepEqual(report.instructionSets.map(set => set.id), ["X64"]);
});
