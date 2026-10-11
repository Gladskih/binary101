import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeInstructionSets } from "../../../../../analyzers/pe/disassembly/analyze.js";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { isaDataBytes, peIsaDataOptions } from "../../../../fixtures/isa-known-data.js";
import { createPeFlowStopFixture } from "../../../../fixtures/pe-flow-stop.js";

for (const machine of [0x14c, 0x8664, 0xaa64]) {
  void test(`PE machine ${machine} stops before data and rejects every metadata seed at that RVA`, async () => {
    const file = new File([isaDataBytes(machine)], "isa-data.exe");
    const opts = peIsaDataOptions(machine);

    const report = await analyzePeInstructionSets(createFileRangeReader(file, 0, file.size), opts);

    assert.equal(report.bytesDecoded, 8);
    assert.equal(report.instructionCount, machine === 0xaa64 ? 2 : 8);
    assert.equal(report.invalidInstructionCount, 0);
    assert.ok(!report.instructionSets.some(set => /AVX|SVE|SME/.test(set.label)));
    assert.ok(report.issues.some(issue => /known data|exported data/.test(issue)));
  });
}

for (const bitness of [32, 64] as const) {
  void test(`PE${bitness} imported pointer cells block interior seeds`, async () => {
    const { file, options } = createPeFlowStopFixture(bitness,
      [...isaDataBytes(bitness === 64 ? 0x8664 : 0x14c)]);
    options.imports!.entries[0]!.firstThunkRva = 0x1008;
    options.exportRvas = [0x100a];
    options.tlsCallbackRvas = [0x100a];

    const report = await analyzePeInstructionSets(file, options);

    assert.equal(report.bytesDecoded, 8);
    assert.ok(!report.instructionSets.some(set => set.id === "AVX"));
    assert.ok(report.issues.some(issue => /points into known data; skipped/.test(issue)));
  });
}

void test("PE AArch64 IAT pointer cells block interior entrypoints", async () => {
  const { options } = createPeFlowStopFixture(64, [...isaDataBytes(0xaa64)]);
  options.coffMachine = 0xaa64;
  options.imports!.entries[0]!.firstThunkRva = 0x1008;
  options.entrypointRva = 0x100c;
  const file = new File([isaDataBytes(0xaa64)], "iat-arm64.exe");

  const report = await analyzePeInstructionSets(createFileRangeReader(file, 0, file.size), options);

  assert.equal(report.bytesDecoded, 8);
  assert.equal(report.instructionCount, 2);
  assert.ok(report.issues.some(issue => /points into known data; skipped/.test(issue)));
});
