import assert from "node:assert/strict";
import { test } from "node:test";
import { Amd64UnwindV12StatisticsBuilder }
  from "../../../../../../analyzers/pe/exception/amd64/unwind-v12-statistics.js";
import { visitAmd64UnwindCodeSlots }
  from "../../../../../../analyzers/pe/exception/amd64/unwind-code-slots.js";
import type { Amd64UnwindV12Header }
  from "../../../../../../analyzers/pe/exception/amd64/unwind-v12-types.js";

const addBlock = (builder: Amd64UnwindV12StatisticsBuilder, bytes: number[],
  header: Amd64UnwindV12Header = { prologSize: 1, frameRegister: 0, frameOffset: 0 }) => {
  const analysis = visitAmd64UnwindCodeSlots(new DataView(Uint8Array.from(bytes).buffer),
    bytes.length / 2, 1, builder.visitOperation);
  builder.recordBlock(header, analysis);
  return analysis;
};

void test("v1/v2 statistics retain zeroes, repeated operands, and distinct register classes", () => {
  const builder = new Amd64UnwindV12StatisticsBuilder();
  const bytes = [1, 2, 1, 1, 32, 0, 1, 0x80, 1, 0x84, 0, 0, 1, 0x88, 0, 0, 0, 10, 1, 3];
  addBlock(builder, bytes, { prologSize: 1, frameRegister: 8, frameOffset: 0 });
  addBlock(builder, bytes, { prologSize: 1, frameRegister: 8, frameOffset: 0 });
  const statistics = builder.build();

  assert.equal(statistics.blockCount, 2);
  assert.equal(statistics.incompleteBlockCount, 0);
  assert.deepEqual(statistics.operationCounts, { ALLOC_SMALL: 2, ALLOC_LARGE: 2,
    PUSH_NONVOL: 2, SAVE_NONVOL: 2, SAVE_XMM128: 2, PUSH_MACHFRAME: 2, SET_FPREG: 2 });
  assert.deepEqual(statistics.allocationCounts, { 8: 2, 256: 2 });
  assert.deepEqual(statistics.registerCounts, { R8: 4, XMM8: 2 });
  assert.deepEqual(statistics.saveOffsetCounts, { 0: 4 });
  assert.deepEqual(statistics.frameRegisterCounts, { R8: 2 });
  assert.deepEqual(statistics.frameOffsetCounts, { 0: 2 });
  assert.deepEqual(statistics.machineFrameCounts, { 40: 2 });
  assert.deepEqual(statistics.prologSizeCounts, { 1: 2 });
});

void test("truncation and unknown encodings mark incomplete blocks while zero-code blocks remain valid", () => {
  const builder = new Amd64UnwindV12StatisticsBuilder();
  const analysis = visitAmd64UnwindCodeSlots(new DataView(new ArrayBuffer(0)), 0, 1, builder.visitOperation);
  builder.recordBlock({ prologSize: 0, frameRegister: 0, frameOffset: 0 }, analysis);
  builder.recordBlock({ prologSize: 0, frameRegister: 0, frameOffset: 0 },
    { ...analysis, isTruncated: true });
  builder.recordBlock({ prologSize: 0, frameRegister: 0, frameOffset: 0 },
    { ...analysis, issues: ["Reserved encoding"] });

  const statistics = builder.build();
  assert.equal(statistics.blockCount, 3);
  assert.equal(statistics.incompleteBlockCount, 2);
  assert.deepEqual(statistics.frameRegisterCounts, {});
  assert.deepEqual(statistics.frameOffsetCounts, {});
  assert.deepEqual(statistics.operationCounts, {});
  assert.deepEqual(statistics.prologSizeCounts, { 0: 3 });
});

// Microsoft x64 EH, "Operation info": this is the architectural encoding,
// independent of the production register-name lookup.
for (const [register, name] of [[0, "RAX"], [1, "RCX"], [2, "RDX"], [3, "RBX"], [4, "RSP"],
  [5, "RBP"], [6, "RSI"], [7, "RDI"], [8, "R8"], [15, "R15"]] as const) {
  void test(`v1/v2 statistics preserve architectural register ${name}`, () => {
    const builder = new Amd64UnwindV12StatisticsBuilder();
    addBlock(builder, [1, register << 4]);

    assert.deepEqual(builder.build().registerCounts, { [name]: 1 });
  });
}

void test("v1/v2 counters retain maximum format fields, full-width operands and first-seen names", () => {
  const builder = new Amd64UnwindV12StatisticsBuilder();
  addBlock(builder, [1, 0xf9, 255, 255, 255, 255, 1, 0x11, 248, 255, 255, 255, 1, 0, 0, 0x1a],
    { prologSize: 255, frameRegister: 15, frameOffset: 240 });
  const statistics = builder.build();
  assert.deepEqual(statistics.allocationCounts, { 4294967288: 1 });
  assert.deepEqual(statistics.saveOffsetCounts, { 4294967295: 1 });
  assert.deepEqual(statistics.registerCounts, { XMM15: 1, RAX: 1 });
  assert.deepEqual(statistics.frameRegisterCounts, { R15: 1 });
  assert.deepEqual(statistics.frameOffsetCounts, { 240: 1 });
  assert.deepEqual(statistics.prologSizeCounts, { 255: 1 });
  assert.deepEqual(statistics.machineFrameCounts, { 48: 1 });
  assert.deepEqual(Object.keys(statistics.operationCounts),
    ["SAVE_XMM128_FAR", "ALLOC_LARGE", "PUSH_NONVOL", "PUSH_MACHFRAME"]);
});

void test("v1/v2 builders retain only validated prefixes and return independent snapshots", () => {
  const builder = new Amd64UnwindV12StatisticsBuilder();
  assert.deepEqual(addBlock(builder, [1, 2, 1, 11, 1, 0]).issues,
    ["AMD64 unwind opcode 11 is unknown or reserved; remaining operations are not decoded."]);
  const first = builder.build();
  addBlock(builder, [1, 2]);
  assert.deepEqual(first.allocationCounts, { 8: 1 });
  assert.deepEqual(first.operationCounts, { ALLOC_SMALL: 1 });
  assert.equal(first.incompleteBlockCount, 1);
  assert.deepEqual(builder.build().allocationCounts, { 8: 2 });
});

void test("v1/v2 counters distinguish XMM0 from every general-purpose register", () => {
  const builder = new Amd64UnwindV12StatisticsBuilder();
  addBlock(builder, [1, 8, 0, 0]); // SAVE_XMM128 with OpInfo=0 encodes XMM0.
  assert.deepEqual(builder.build().registerCounts, { XMM0: 1 });
});
