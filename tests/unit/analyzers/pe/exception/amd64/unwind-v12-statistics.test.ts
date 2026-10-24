import assert from "node:assert/strict";
import { test } from "node:test";
import { createV12Statistics, recordV12Statistics }
  from "../../../../../../analyzers/pe/exception/amd64/unwind-v12-statistics.js";
import type { Amd64UnwindCodeAnalysis }
  from "../../../../../../analyzers/pe/exception/amd64/unwind-code-slots.js";

void test("v1/v2 statistics retain zeroes, repeated operands, and distinct register classes", () => {
  const statistics = createV12Statistics();
  const analysis: Amd64UnwindCodeAnalysis = { operations: [
    { opcode: "ALLOC_SMALL", size: 8, codeOffset: 1 },
    { opcode: "ALLOC_LARGE", size: 256, codeOffset: 1 },
    { opcode: "PUSH_NONVOL", register: 8, codeOffset: 1 },
    { opcode: "SAVE_NONVOL", register: 8, displacement: 0, codeOffset: 1 },
    { opcode: "SAVE_XMM128", register: 8, displacement: 0, codeOffset: 1 },
    { opcode: "PUSH_MACHFRAME", size: 40, codeOffset: 0 },
    { opcode: "SET_FPREG", codeOffset: 1 }
  ], issues: [], isTruncated: false, epilogScopeCount: 0, hasEpilogInfo: false, hasLateEpilogCode: false };
  recordV12Statistics(statistics, { prologSize: 1, frameRegister: 8, frameOffset: 0 }, analysis);
  recordV12Statistics(statistics, { prologSize: 1, frameRegister: 8, frameOffset: 0 }, analysis);

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
  const statistics = createV12Statistics();
  const analysis: Amd64UnwindCodeAnalysis = { operations: [], issues: [], isTruncated: false,
    epilogScopeCount: 0, hasEpilogInfo: false, hasLateEpilogCode: false };
  recordV12Statistics(statistics, { prologSize: 0, frameRegister: 0, frameOffset: 0 }, analysis);
  recordV12Statistics(statistics, { prologSize: 0, frameRegister: 0, frameOffset: 0 },
    { ...analysis, isTruncated: true });
  recordV12Statistics(statistics, { prologSize: 0, frameRegister: 0, frameOffset: 0 },
    { ...analysis, issues: ["Reserved encoding"] });

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
    const statistics = createV12Statistics();
    recordV12Statistics(statistics, { prologSize: 1, frameRegister: 0, frameOffset: 0 }, {
      operations: [{ opcode: "PUSH_NONVOL", codeOffset: 1, register }], issues: [],
      isTruncated: false, epilogScopeCount: 0, hasEpilogInfo: false, hasLateEpilogCode: false
    });

    assert.deepEqual(statistics.registerCounts, { [name]: 1 });
  });
}
