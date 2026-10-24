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
  Uint8Array.from([0xe8]), Uint8Array.from([0xef]), Uint8Array.from([0xee]),
  Uint8Array.from([0xf5]), Uint8Array.from([0xf8, 0x01, 0x02]),
  Uint8Array.from([0xf9, 0x01]), Uint8Array.from([0xfa, 0x01, 0x02]),
  Uint8Array.from([0xf0, 0x02]), Uint8Array.from([0xef, 0x10]),
  Uint8Array.from([0xee, 0x10])]) {
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

for (const [name, bytes, stack, integer, floating, frame, returns, marker] of [
  ["stack add boundaries", [0x00, 0x7f, 0xff], [0, 508], 0, 0, 0, 0, "end"],
  ["16-bit and 32-bit core-register pops", [0xec, 0x81, 0xd7, 0xdb, 0xff], [], 15, 0, 0, 1, "end"],
  ["32-bit pop register-group endpoints", [0xd8, 0xdf, 0xff], [], 14, 0, 0, 1, "end"],
  ["SP restore and VFP pop boundaries", [0xc0, 0xcf, 0xe0, 0xe7, 0xff], [], 0, 9, 2, 0, "end"],
  ["wide stack adjustment boundaries", [0xe8, 1, 0xeb, 2, 0xff], [4, 3080], 0, 0, 0, 0, "end"],
  ["extended stack adjustment boundaries", [0xf7, 1, 2, 0xf8, 0, 0, 3, 0xf9, 0, 4, 0xfa, 0, 0, 5, 0xff],
    [1032, 12, 16, 20], 0, 0, 0, 0, "end"],
  ["extended VFP ranges and LR load", [0xf5, 0x23, 0xf6, 0x12, 0xef, 0x0f, 0xff], [], 0, 4, 0, 1, "end"]
] as const) {
  void test(`ARMNT summarizes ${name}`, () => {
    const summary = summarizeArmntOpcodes(Uint8Array.from(bytes));
    assert.deepEqual(summary.stackAdjustments, stack);
    assert.equal(summary.integerRegisterPopCount, integer);
    assert.equal(summary.floatingRegisterPopCount, floating);
    assert.equal(summary.framePointerRestores, frame);
    assert.equal(summary.returnAddressLoads, returns);
    assert.equal(summary.specialMarkers[marker], 1);
    assert.equal(summary.complete, true);
  });
}

void test("ARMNT retains available Microsoft markers and rejects invalid extended register ranges", () => {
  const available = summarizeArmntOpcodes(Uint8Array.from([0xee, 0x0f, 0xfb, 0xff]));
  const endWithNop = [0xfd, 0xfe].map(opcode => summarizeArmntOpcodes(Uint8Array.from([opcode])));
  const invalid = summarizeArmntOpcodes(Uint8Array.from([0xf5, 0xf0]));

  assert.equal(available.specialMarkers["Microsoft-specific operation"], 1);
  assert.equal(available.specialMarkers["NOP"], 1);
  assert.deepEqual(endWithNop.map(summary => summary.specialMarkers["end with NOP"]), [1, 1]);
  assert.equal(available.complete, true);
  assert.equal(invalid.complete, false);
  assert.equal(invalid.unknownOpcodeCount, 1);
});
