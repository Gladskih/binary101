import assert from "node:assert/strict";
import { test } from "node:test";
import { createV3Unwind } from "../../../../../fixtures/pe-unwind-v3.js";
import { decodeAmd64UnwindV3 } from "../../../../../../analyzers/pe/exception/amd64/unwind-v3.js";
import { createV3Statistics, recordV3Statistics } from "../../../../../../analyzers/pe/exception/amd64/unwind-v3-statistics.js";

void test("V3 statistics start empty and still count an unreadable version-3 block", () => {
  const statistics = createV3Statistics();
  recordV3Statistics(statistics, null);

  assert.deepEqual(statistics, { blockCount: 1, epilogCount: 0, inheritedEpilogCount: 0,
    largePrologCount: 0, largeEpilogCount: 0, prologSizeCounts: {}, operationCounts: {},
    registerCounts: {}, allocationCounts: {}, canonicalFrameTypeCounts: {} });
  assert.notEqual(createV3Statistics(), statistics);
});

void test("V3 shared pool operations count once per block and register operands stay meaningful", () => {
  const statistics = createV3Statistics();
  const issues: string[] = [];
  // PUSH R31, PUSH_CONSECUTIVE_2 R16/R17, PUSH2 RBX/RDI,
  // SET_FPREG RBP, SAVE_XMM128 XMM6, ALLOC_SMALL 32, canonical frame type 255.
  const record = decodeAmd64UnwindV3(createV3Unwind([
    6, 5, 4, 3, 2, 1, 0, 0xfc, 0x87, 0xe0, 0x38, 0, 5, 0x6a, 2, 0, 0x38, 3, 255
  ], 7, 0, 7), issues);
  assert.ok(record);
  recordV3Statistics(statistics, { ...record, epilogs: [
    { kind: "full", flags: 2, offset: -10, firstOp: 0, lastInstructionOffset: 9,
      ipOffsets: [0, 1, 2, 3, 4, 5, 6], operations: record.prologOperations },
    { kind: "inherited", flags: 2, offset: -20, baseEpilogIndex: 0 }
  ] });

  assert.deepEqual(statistics.registerCounts, { R31: 1, R16: 1, R17: 1, RBX: 1, RDI: 1, RBP: 1, XMM6: 1 });
  assert.deepEqual(statistics.allocationCounts, { 32: 1 });
  assert.deepEqual(statistics.canonicalFrameTypeCounts, { 255: 1 });
  assert.equal(statistics.epilogCount, 2);
  assert.equal(statistics.inheritedEpilogCount, 1);
  assert.equal(statistics.largeEpilogCount, 2);
  assert.equal(statistics.largePrologCount, 0);
  assert.deepEqual(statistics.operationCounts, { PUSH: 1, PUSH_CONSECUTIVE_2: 1, PUSH2: 1,
    SET_FPREG: 1, SAVE_XMM128: 1, ALLOC_SMALL: 1, PUSH_CANONICAL_FRAME: 1 });
  assert.deepEqual(issues, []);
});

void test("V3 records accumulate independent blocks, LARGE prologs, and separate epilog operations", () => {
  const statistics = createV3Statistics();
  const record = { flags: 8, prologSize: 256, prologIpOffsets: [], prologOperations: [],
    epilogs: [{ kind: "full" as const, flags: 0, offset: 0, firstOp: 0,
      lastInstructionOffset: 1, ipOffsets: [0], operations: [{ opcode: "PUSH" as const, register: 0 }] }] };
  recordV3Statistics(statistics, record);
  recordV3Statistics(statistics, record);

  assert.equal(statistics.blockCount, 2);
  assert.equal(statistics.largePrologCount, 2);
  assert.deepEqual(statistics.prologSizeCounts, { 256: 2 });
  assert.deepEqual(statistics.operationCounts, { PUSH: 2 });
  assert.deepEqual(statistics.registerCounts, { RAX: 2 });
  assert.equal(statistics.largeEpilogCount, 0);
});

// Unchanged LLVM's AMD64/APX register numbering.
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/lib/Support/Win64EH.cpp
for (const [register, name] of ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
  "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "R16", "R17", "R18", "R19",
  "R20", "R21", "R22", "R23", "R24", "R25", "R26", "R27", "R28", "R29", "R30", "R31"].entries()) {
  void test(`V3 register statistics retain ${name}`, () => {
    const statistics = createV3Statistics();
    recordV3Statistics(statistics, { flags: 0, prologSize: 16, prologIpOffsets: [0],
      prologOperations: [{ opcode: "PUSH", register }], epilogs: [] });

    assert.deepEqual(statistics.registerCounts, { [name]: 1 });
  });
}
