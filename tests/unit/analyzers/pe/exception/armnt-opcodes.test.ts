import assert from "node:assert/strict";
import { test } from "node:test";
import { summarizeArmntOpcodeSequences, summarizeArmntOpcodes } from "../../../../../analyzers/pe/exception/armnt-opcodes.js";

void test("ARMNT unwind opcodes summarize stack changes and saved register classes", () => {
  const summary = summarizeArmntOpcodes(Uint8Array.from([4, 0xa4, 0x05, 0xe2, 0xff]));

  assert.deepEqual(summary, { opcodeCounts: { "stack add 16-bit": 1,
    "register pop 32-bit": 1, "VFP pop": 1, end: 1 }, instructionCount: 4, complete: true, stackAdjustments: [16],
    integerRegisterPopCount: 3, floatingRegisterPopCount: 3, framePointerRestores: 0,
    returnAddressLoads: 1, specialMarkers: { end: 1 }, unknownOpcodeCount: 0 });
});

void test("ARMNT unwind opcodes keep big endian operands and wide adjustment units", () => {
  const summary = summarizeArmntOpcodes(Uint8Array.from([0xf7, 0x01, 0x02, 0xf5, 0x23, 0xff]));

  assert.deepEqual(summary.stackAdjustments, [0x408]);
  assert.equal(summary.floatingRegisterPopCount, 2);
  assert.equal(summary.complete, true);
});

for (const codes of [Uint8Array.from([0x80]), Uint8Array.from([0xf7, 0x01]),
  Uint8Array.from([0xf0, 0x02])]) {
  void test(`ARMNT stops safely at truncated or reserved code ${[...codes].join(" ")}`, () => {
    const summary = summarizeArmntOpcodes(codes);
    assert.equal(summary.complete, false);
    assert.equal(summary.unknownOpcodeCount, 1);
    assert.equal(summary.instructionCount, 1);
  });
}

void test("ARMNT decodes each shared epilogue tail once and rejects an out-of-pool index", () => {
  const summary = summarizeArmntOpcodeSequences(Uint8Array.from([0x04, 0xff]), [0, 0, 2]);

  assert.deepEqual(summary.stackAdjustments, [16]);
  assert.equal(summary.complete, false);
  assert.equal(summary.instructionCount, 2);
});
