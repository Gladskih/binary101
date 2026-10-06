import assert from "node:assert/strict";
import test from "node:test";
import { collectPeDisassemblySeeds } from "../../../../../ui/pe-disassembly-seeds.js";
import { createPeDisassemblyController } from "../../../../../ui/pe-disassembly.js";
import { analyzePeInstructionSets } from "../../../../../analyzers/pe/disassembly/index.js";
import type { AnalyzePeInstructionSetOptions, PeInstructionSetReport } from
  "../../../../../analyzers/pe/disassembly/types.js";
import type { ParseForUiResult } from "../../../../../analyzers/index.js";
import { createReadyToRunSeedFixture } from "../../../../helpers/ready-to-run-seed-fixture.js";
import { installFakeDom, flushTimers } from "../../../../helpers/fake-dom.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { createPeReadyToRunSeedFile, createPeReadyToRunInstanceSeedFile } from
  "../../../../fixtures/pe-ready-to-run-seed-file.js";
import { createPeReadyToRunThunkFile, createPeExportedReadyToRunFile,
  createPeClrFreeReadyToRunFile } from "../../../../fixtures/pe-ready-to-run-thunk-file.js";

void test("full parsing supplies instruction starts from thunks while excluding import data cells", async () => {
  const file = createPeReadyToRunThunkFile();
  const pe = await parsePe(file);
  assert.ok(pe && isPeWindowsParseResult(pe));

  const seeds = await collectPeDisassemblySeeds(file, pe);

  assert.deepEqual(seeds.extraEntrypoints, [
    { source: "ReadyToRun runtime functions", rvas: [0x1020] },
    { source: "ReadyToRun import thunks", rvas: [0x1040] }
  ]);
  assert.deepEqual(pe.clr?.readyToRun?.issues, []);
  assert.deepEqual(seeds.issues, []);
});

void test("full parsing follows RTR_HEADER exports when ManagedNativeHeader is absent", async () => {
  const pe = await parsePe(createPeExportedReadyToRunFile());
  assert.ok(pe && isPeWindowsParseResult(pe));

  assert.equal(pe.clr?.readyToRun?.status, "ready-to-run");
  assert.equal(pe.clr?.readyToRun?.sections[2]?.decoded?.kind, "thunks");
  assert.equal(pe.readyToRun, undefined);
});

void test("CLR-free exported R2R headers feed native seeds without fabricating a CLR header", async () => {
  const file = createPeClrFreeReadyToRunFile();
  const pe = await parsePe(file);
  assert.ok(pe && isPeWindowsParseResult(pe));

  const seeds = await collectPeDisassemblySeeds(file, pe);

  assert.equal(pe.clr, null);
  assert.equal(pe.readyToRun?.status, "ready-to-run");
  assert.equal(pe.readyToRun?.sections[2]?.decoded?.kind, "thunks");
  assert.deepEqual(seeds.extraEntrypoints, [
    { source: "ReadyToRun runtime functions", rvas: [0x1020] },
    { source: "ReadyToRun import thunks", rvas: [0x1040] }
  ]);
});

void test("full PE parsing supplies R2R method roots without an exception directory", async () => {
  const file = createPeReadyToRunSeedFile();
  const pe = await parsePe(file);
  assert.ok(pe && isPeWindowsParseResult(pe));

  const seeds = await collectPeDisassemblySeeds(file, pe);

  // Fixture's native method is separate from its RET-only PE entrypoint.
  assert.deepEqual(seeds.extraEntrypoints, [
    { source: "ReadyToRun runtime functions", rvas: [0x1020] }
  ]);
  assert.deepEqual(seeds.unwindBeginRvas, []);
  assert.deepEqual(seeds.issues, []);
});

void test("full PE parsing reports invalid R2R references to the disassembly seed collector", async () => {
  const file = createPeReadyToRunSeedFile(1);
  const pe = await parsePe(file);
  assert.ok(pe && isPeWindowsParseResult(pe));

  const seeds = await collectPeDisassemblySeeds(file, pe);

  assert.deepEqual(seeds.extraEntrypoints, [{ source: "ReadyToRun runtime functions", rvas: [0x1020] }]);
  assert.match(seeds.issues.join(" "), /missing runtime-function index/);
  assert.match(pe.clr!.readyToRun!.issues.join(" "), /missing runtime-function index/);
});

void test("full PE parsing forwards generic instance roots when there is no MethodDef map", async () => {
  const file = createPeReadyToRunInstanceSeedFile();
  const pe = await parsePe(file);
  assert.ok(pe && isPeWindowsParseResult(pe));

  const seeds = await collectPeDisassemblySeeds(file, pe);

  assert.deepEqual(seeds.extraEntrypoints, [
    { source: "ReadyToRun runtime functions", rvas: [0x1020] }
  ]);
  assert.equal(pe.clr?.readyToRun?.sections.some(section => section.type === 103), false);
  assert.deepEqual(seeds.issues, []);
});

void test("PE seed collection forwards R2R native roots without exception metadata", async () => {
  const fixture = createReadyToRunSeedFixture();

  const seeds = await collectPeDisassemblySeeds(fixture.file, fixture.pe);

  assert.deepEqual(seeds.extraEntrypoints, [
    { source: "ReadyToRun runtime functions", rvas: fixture.codeRvas }
  ]);
  assert.deepEqual(seeds.unwindBeginRvas, []);
  assert.deepEqual(seeds.issues, []);
});

void test("the native disassembler visits both independent R2R method roots", async () => {
  const fixture = createReadyToRunSeedFixture();
  const seeds = await collectPeDisassemblySeeds(fixture.file, fixture.pe);

  const report = await analyzePeInstructionSets(fixture.reader, {
    coffMachine: seeds.canonicalMachine, is64Bit: true, imageBase: fixture.pe.opt.ImageBase,
    entrypointRva: seeds.entrypointRva, extraEntrypoints: seeds.extraEntrypoints,
    sections: fixture.pe.sections, rvaToOff: fixture.pe.rvaToOff
  });

  assert.equal(report.instructionCount, 2);
  assert.equal(report.invalidInstructionCount, 0);
  assert.deepEqual(report.issues, []);
});

const emptyReport = (): PeInstructionSetReport => ({ bitness: 64, bytesSampled: 0,
  bytesDecoded: 0, instructionCount: 0, invalidInstructionCount: 0,
  directIatReferences: [], codeStringReferences: [], specialInstructions: [],
  apiStringReferences: [], instructionSets: [], issues: ["existing decoder warning"] });

void test("PE controller forwards valid R2R roots and renders seed warnings with decoder warnings", async () => {
  const dom = installFakeDom();
  const fixture = createReadyToRunSeedFixture(0x8664, [0, 2]);
  const parsed: ParseForUiResult = { analyzer: "pe", parsed: fixture.pe };
  const captured: AnalyzePeInstructionSetOptions[] = [];
  const report = emptyReport();
  const rendered: ParseForUiResult[] = [];
  const controller = createPeDisassemblyController({ getCurrentFile: () => fixture.file,
    getCurrentParseResult: () => parsed, renderResult: result => rendered.push(result),
    analyze: async (_reader, options) => { captured.push(options); return report; } });

  controller.start(fixture.file, fixture.pe);
  await flushTimers();

  assert.deepEqual(captured[0]!.extraEntrypoints, [
    { source: "ReadyToRun runtime functions", rvas: fixture.codeRvas }
  ]);
  assert.deepEqual(fixture.pe.disassembly?.issues, [
    "ReadyToRun disassembly seeds: method map references a missing runtime-function index.",
    "existing decoder warning"
  ]);
  assert.deepEqual(report.issues, ["existing decoder warning"]);
  assert.deepEqual(rendered, [parsed]);
  dom.restore();
});
