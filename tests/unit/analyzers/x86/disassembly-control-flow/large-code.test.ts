import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86-disasm";
import { disassembleControlFlowForInstructionSets }
  from "../../../../../analyzers/x86/disassembly-control-flow.js";
import { disassembleControlFlowForInstructionSetsVaddr }
  from "../../../../../analyzers/x86/disassembly-control-flow-vaddr.js";

const createLargeLinearCode = (): Uint8Array => {
  // Regression: the observed Set limit was 2^24 distinct instruction addresses.
  // Intel SDM Vol. 2: 90 is NOP and C3 is RET, each one byte long.
  const bytes = new Uint8Array(0x1000002).fill(0x90);
  bytes[bytes.length - 1] = 0xc3;
  return bytes;
};

void test("PE x86 traversal completes beyond the former Set limit", async () => {
  const data = createLargeLinearCode();
  const issues: string[] = [];

  const result = await disassembleControlFlowForInstructionSets({
    iced, bitness: 32, imageBase: 0x400000n, sections: [{ rvaStart: 0x1000, data }],
    entrypoints: [0x1000, 0x1000], yieldEveryInstructions: 0, featureCounts: new Map(), issues
  });

  assert.equal(result.instructionCount, data.length);
  assert.equal(result.bytesDecoded, data.length);
  assert.equal(result.invalidInstructionCount, 0);
  assert.deepEqual(issues, []);
});

void test("ELF x64 traversal completes beyond the former Set limit at a high address", async () => {
  const data = createLargeLinearCode();
  const issues: string[] = [];
  // Keep every bit of an address beyond Number.MAX_SAFE_INTEGER.
  const vaddrStart = 0xffff800000001001n;

  const result = await disassembleControlFlowForInstructionSetsVaddr({
    iced, bitness: 64, sections: [{ vaddrStart, data }], entrypoints: [vaddrStart, vaddrStart],
    yieldEveryInstructions: 0, featureCounts: new Map(), issues
  });

  assert.equal(result.instructionCount, data.length);
  assert.equal(result.bytesDecoded, data.length);
  assert.equal(result.invalidInstructionCount, 0);
  assert.deepEqual(issues, []);
});
