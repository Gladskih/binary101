"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { analyzePeInstructionSets } from "../../../../../analyzers/pe/disassembly/analyze.js";
import { createPeFlowStopFixture, directIatCall } from "../../../../fixtures/pe-flow-stop.js";

for (const bitness of [32, 64] as const) {
  void test(`ISA ${bitness} stops after an imported noReturn call but retains an independent seed`, async () => {
    // Data after CALL spells MOVAPS / RET. The last RET is independently seeded code.
    const { file, options } = createPeFlowStopFixture(bitness,
      [...directIatCall(bitness), 0x0f, 0x28, 0xc0, 0xc3, 0xc3]);
    options.exportRvas = [0x100a];

    const report = await analyzePeInstructionSets(file, options);

    assert.equal(report.instructionCount, 2);
    assert.equal(report.bytesDecoded, 7);
    assert.equal(report.instructionSets.some(feature => feature.id === "SSE"), false);
    assert.deepEqual(report.directIatReferences, [{ slotRva: 0x2000,
      callReferenceCount: 1, jumpReferenceCount: 0 }]);
  });
}

void test("ISA stops before an exported data start reached by fallthrough", async () => {
  const { file, options } = createPeFlowStopFixture(64, [0x90, 0x0f, 0x28, 0xc0, 0xc3]);
  const configured = { ...options, dataRvas: [0x1001] };

  const report = await analyzePeInstructionSets(file, configured);

  assert.equal(report.instructionCount, 1);
  assert.equal(report.bytesDecoded, 1);
  assert.equal(report.instructionSets.some(feature => feature.id === "SSE"), false);
  assert.deepEqual(report.issues, ["Stopped before known data at RVA 0x1001."]);
});

void test("ISA rejects an instruction crossing an exported data start", async () => {
  const { file, options } = createPeFlowStopFixture(64, [0xb8, 1, 0, 0, 0, 0xc3]);

  const report = await analyzePeInstructionSets(file, { ...options, dataRvas: [0x1002] });

  assert.equal(report.instructionCount, 0);
  assert.equal(report.bytesDecoded, 0);
  assert.deepEqual(report.issues, ["Stopped before known data at RVA 0x1002."]);
});

void test("an unwind seed does not override exported data evidence, while unrelated code remains", async () => {
  const { file, options } = createPeFlowStopFixture(64, [0xc3, 0x0f, 0x28, 0xc0, 0xc3, 0xc3]);
  options.dataRvas = [0x1001];
  options.unwindBeginRvas = [0x1001];
  options.exportRvas = [0x1005];

  const report = await analyzePeInstructionSets(file, options);

  assert.equal(report.instructionCount, 2);
  assert.equal(report.instructionSets.some(feature => feature.id === "SSE"), false);
  assert.deepEqual(report.issues, ["Unwind RVA 0x1001 points into known data; skipped."]);
});

void test("a direct call into known exported data is diagnosed instead of decoding the data", async () => {
  const { file, options } = createPeFlowStopFixture(64,
    [0xe8, 3, 0, 0, 0, 0xc3, 0x90, 0x90, 0x0f, 0x28, 0xc0, 0xc3]);
  options.dataRvas = [0x1008];

  const report = await analyzePeInstructionSets(file, options);

  assert.equal(report.instructionCount, 2);
  assert.equal(report.instructionSets.some(feature => feature.id === "SSE"), false);
  assert.deepEqual(report.issues, ["Stopped before known data at RVA 0x1008."]);
});

void test("invalid data RVAs are ignored without wrapping into code addresses", async () => {
  const { file, options } = createPeFlowStopFixture(64, [0x90, 0xc3]);
  options.dataRvas = [-1, 0x1_0000_1000, Number.NaN, 0x1000 + 0.5];

  const report = await analyzePeInstructionSets(file, options);

  assert.equal(report.instructionCount, 2);
  assert.deepEqual(report.issues, []);
});
