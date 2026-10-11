"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { analyzePeInstructionSets } from "../../../../../analyzers/pe/disassembly/analyze.js";
import { createPeNoReturnCallPredicate } from "../../../../../analyzers/pe/disassembly/no-return-calls.js";
import { createPeFlowStopFixture, createPeImportThunkFixture,
  directIatCall, setPeFlowStopMetadata } from "../../../../fixtures/pe-flow-stop.js";

for (const bitness of [32, 64] as const) {
  void test(`ISA ${bitness} follows an import thunk but stops its noReturn caller`, async () => {
    const { file, options } = createPeImportThunkFixture(bitness);

    const report = await analyzePeInstructionSets(file, options);

    assert.equal(report.instructionCount, 2);
    assert.equal(report.bytesDecoded, 11);
    assert.deepEqual(report.directIatReferences, [{ slotRva: 0x2000,
      callReferenceCount: 0, jumpReferenceCount: 1 }]);
    assert.equal(report.instructionSets.some(feature => feature.id === "SSE"), false);
  });
}

for (const metadata of ["returning", "missing", "legacy", "overlap", "invalid-slot"] as const) {
  void test(`ISA respects ${metadata} import metadata without guessing from the name`, async () => {
    const { file, options } = createPeFlowStopFixture(32,
      [...directIatCall(32), 0x0f, 0x28, 0xc0, 0xc3]);
    setPeFlowStopMetadata(options, metadata);

    const report = await analyzePeInstructionSets(file, options);

    assert.equal(report.instructionCount, metadata === "legacy" ? 1 : 3);
    assert.equal(report.instructionSets.some(feature => feature.id === "SSE"), metadata !== "legacy");
  });
}

void test("ISA also honors noReturn metadata on delay imports", async () => {
  const { file, options } = createPeFlowStopFixture(32,
    [...directIatCall(32), 0x0f, 0x28, 0xc0, 0xc3]);
  options.delayImports = { entries: [{ name: "kernel32.dll", Attributes: 1,
    ModuleHandleRVA: 0, ImportAddressTableRVA: 0x2000, ImportNameTableRVA: 0,
    BoundImportAddressTableRVA: 0, UnloadInformationTableRVA: 0, TimeDateStamp: 0,
    functions: options.imports!.entries[0]!.functions }] };
  delete options.imports;

  const report = await analyzePeInstructionSets(file, options);

  assert.equal(report.instructionCount, 1);
  assert.equal(report.instructionSets.some(feature => feature.id === "SSE"), false);
});

void test("an exported data object cannot be inferred as a noReturn import thunk", async () => {
  const { file, options } = createPeImportThunkFixture(64);
  options.dataRvas = [0x1012];

  const report = await analyzePeInstructionSets(file, options);

  assert.equal(report.instructionCount, 3);
  assert.equal(report.instructionSets.some(feature => feature.id === "SSE"), true);
  assert.deepEqual(report.issues, ["Stopped before exported data at RVA 0x1012."]);
});

void test("an unmapped direct call target does not suppress the caller continuation", async () => {
  // CALL rel32 reaches outside the sampled executable section.
  const { file, options } = createPeFlowStopFixture(64,
    [0xe8, 0xfb, 0x7f, 0, 0, 0x0f, 0x28, 0xc0, 0xc3]);

  const report = await analyzePeInstructionSets(file, options);

  assert.equal(report.instructionCount, 3);
  assert.equal(report.instructionSets.some(feature => feature.id === "SSE"), true);
});

void test("a direct call to an ordinary returning function keeps its fallthrough", async () => {
  const { file, options } = createPeImportThunkFixture(32);
  file.data[16] = 0xc3;
  const fixture = createPeFlowStopFixture(32, [...file.data]);

  const report = await analyzePeInstructionSets(fixture.file, options);

  assert.equal(report.instructionCount, 4);
  assert.equal(report.instructionSets.some(feature => feature.id === "SSE"), true);
});

void test("repeated calls decode a mapped import thunk only once", async context => {
  const iced = await import("iced-x86-disasm");
  const { file, options } = createPeImportThunkFixture(64);
  const decoder = new iced.Decoder(64, file.data, iced.DecoderOptions.None);
  decoder.ip = options.imageBase + 0x1000n;
  const call = decoder.decode();
  const decode = context.mock.method(iced.Decoder.prototype, "decode");
  const freeDecoder = context.mock.method(iced.Decoder.prototype, "free");
  const freeInstruction = context.mock.method(iced.Instruction.prototype, "free");
  const predicate = createPeNoReturnCallPredicate(iced, options, [{ rvaStart: 0x1000, data: file.data }]);

  assert.equal(predicate(call), true);
  assert.equal(predicate(call), true);

  assert.equal(decode.mock.callCount(), 1);
  assert.equal(freeDecoder.mock.callCount(), 1);
  assert.equal(freeInstruction.mock.callCount(), 1);
  call.free();
  decoder.free();
});

void test("thunk resolution excludes both section boundaries and caches unmapped targets", async context => {
  const iced = await import("iced-x86-disasm");
  const { file, options } = createPeImportThunkFixture(64);
  // CALL rel32 targets: 0x100f (before), 0x1016 (end), 0x1010 (start).
  const decoder = new iced.Decoder(64,
    new Uint8Array([0xe8, 10, 0, 0, 0, 0xe8, 12, 0, 0, 0, 0xe8, 1, 0, 0, 0]), iced.DecoderOptions.None);
  decoder.ip = options.imageBase + 0x1000n;
  const before = decoder.decode();
  const end = decoder.decode();
  const start = decoder.decode();
  const decode = context.mock.method(iced.Decoder.prototype, "decode");
  const predicate = createPeNoReturnCallPredicate(iced, options,
    [{ rvaStart: 0x1010, data: file.data.subarray(16) }]);

  assert.equal(predicate(before), false);
  assert.equal(predicate(before), false);
  assert.equal(predicate(end), false);
  assert.equal(decode.mock.callCount(), 0);
  assert.equal(predicate(start), true);

  assert.equal(decode.mock.callCount(), 1);
  before.free();
  end.free();
  start.free();
  decoder.free();
});

void test("a noReturn IAT jump is not itself a noReturn call", async () => {
  const iced = await import("iced-x86-disasm");
  const { file, options } = createPeImportThunkFixture(64);
  const decoder = new iced.Decoder(64, file.data.subarray(16), iced.DecoderOptions.None);
  decoder.ip = options.imageBase + 0x1010n;
  const jump = decoder.decode();
  const predicate = createPeNoReturnCallPredicate(iced, options,
    [{ rvaStart: 0x1010, data: file.data.subarray(16) }]);

  assert.equal(predicate(jump), false);
  delete options.imports;
  const withoutMetadata = createPeNoReturnCallPredicate(iced, options, []);

  assert.equal(withoutMetadata(jump), false);
  jump.free();
  decoder.free();
});

void test("a direct jump to a noReturn import thunk is not a call", async () => {
  const iced = await import("iced-x86-disasm");
  const { file, options } = createPeImportThunkFixture(64);
  file.data[0] = 0xe9; // Intel SDM: E9 rel32 is JMP, while E8 rel32 is CALL.
  const decoder = new iced.Decoder(64, file.data, iced.DecoderOptions.None);
  decoder.ip = options.imageBase + 0x1000n;
  const jump = decoder.decode();
  const predicate = createPeNoReturnCallPredicate(iced, options,
    [{ rvaStart: 0x1000, data: file.data }]);

  assert.equal(predicate(jump), false);

  jump.free();
  decoder.free();
});

void test("a failed thunk decode releases its decoder", async context => {
  const iced = await import("iced-x86-disasm");
  const { file, options } = createPeImportThunkFixture(64);
  const decoder = new iced.Decoder(64, file.data, iced.DecoderOptions.None);
  decoder.ip = options.imageBase + 0x1000n;
  const call = decoder.decode();
  context.mock.method(iced.Decoder.prototype, "decode", () => { throw new Error("decode failed"); });
  const free = context.mock.method(iced.Decoder.prototype, "free");
  const predicate = createPeNoReturnCallPredicate(iced, options,
    [{ rvaStart: 0x1000, data: file.data }]);

  assert.throws(() => predicate(call), /decode failed/);

  assert.equal(free.mock.callCount(), 1);
  call.free();
  decoder.free();
});

void test("an explicit returning API entry takes precedence over legacy noReturn metadata", async () => {
  const { file, options } = createPeFlowStopFixture(32,
    [...directIatCall(32), 0x0f, 0x28, 0xc0, 0xc3]);
  const imported = options.imports!.entries[0]!.functions[0]!;
  imported.winapiMetadata = { ...imported.apiMetadata!, sourceKind: "winapi" };
  imported.apiMetadata!.noReturn = false;

  const report = await analyzePeInstructionSets(file, options);

  assert.equal(report.instructionCount, 3);
  assert.equal(report.instructionSets.some(feature => feature.id === "SSE"), true);
});

void test("a truncated import thunk cannot suppress the caller continuation", async () => {
  const { file, options } = createPeImportThunkFixture(32);
  const truncated = createPeFlowStopFixture(32, [...file.data.subarray(0, 19)]);
  truncated.options.imports = options.imports!;

  const report = await analyzePeInstructionSets(truncated.file, truncated.options);

  assert.equal(report.instructionCount, 4);
  assert.equal(report.invalidInstructionCount, 1);
  assert.equal(report.instructionSets.some(feature => feature.id === "SSE"), true);
});
