"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  getNearBranchEdges,
  getNearBranchTarget,
  hasNearBranchOperand
} from "../../../../analyzers/x86/disassembly-branch-targets.js";

const opKinds = {
  NearBranch16: 1,
  NearBranch32: 2,
  NearBranch64: 3,
  Memory: 24
};

void test("hasNearBranchOperand recognizes iced-x86 near branch operand kinds", () => {
  assert.equal(hasNearBranchOperand(1, opKinds), true);
  assert.equal(hasNearBranchOperand(2, opKinds), true);
  assert.equal(hasNearBranchOperand(3, opKinds), true);
  assert.equal(hasNearBranchOperand(24, opKinds), false);
});

void test("getNearBranchTarget returns only statically encoded branch targets", () => {
  assert.equal(getNearBranchTarget({ op0Kind: 2, nearBranchTarget: 0x401000n, nextIP: 0x400ffbn }, opKinds), 0x401000n);
  assert.equal(getNearBranchTarget({ op0Kind: 24, nearBranchTarget: 0x401000n, nextIP: 0x400ffbn }, opKinds), null);
});

void test("getNearBranchEdges returns branch and fallthrough addresses", () => {
  assert.deepEqual(
    getNearBranchEdges({ op0Kind: 3, nearBranchTarget: 0x40100an, nextIP: 0x401008n }, opKinds),
    { branchTarget: 0x40100an, fallthroughTarget: 0x401008n }
  );
});
