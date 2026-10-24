import assert from "node:assert/strict";
import { test } from "node:test";
import { amd64UnwindOperationSlots, decodeAmd64UnwindOperation }
  from "../../../../../../analyzers/pe/exception/amd64/unwind-operations.js";

const viewOf = (bytes: number[]): DataView => new DataView(Uint8Array.from(bytes).buffer);

// Operand widths, scaling, and register numbering are independent spec vectors.
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-unwind_code
const operations = [
  { bytes: [7, 0xf0], body: { opcode: "PUSH_NONVOL", register: 15 }, slots: 1 },
  { bytes: [7, 1, 255, 255], body: { opcode: "ALLOC_LARGE", size: 524280 }, slots: 2 },
  { bytes: [7, 0x11, 248, 255, 255, 255], body: { opcode: "ALLOC_LARGE", size: 4294967288 }, slots: 3 },
  { bytes: [7, 0xf2], body: { opcode: "ALLOC_SMALL", size: 128 }, slots: 1 },
  { bytes: [7, 3], body: { opcode: "SET_FPREG" }, slots: 1 },
  { bytes: [7, 0x34, 255, 255], body: { opcode: "SAVE_NONVOL", register: 3, displacement: 524280 }, slots: 2 },
  { bytes: [7, 0x65, 255, 255, 255, 255],
    body: { opcode: "SAVE_NONVOL_FAR", register: 6, displacement: 4294967295 }, slots: 3 },
  { bytes: [7, 0x78, 255, 255], body: { opcode: "SAVE_XMM128", register: 7, displacement: 1048560 }, slots: 2 },
  { bytes: [7, 0xf9, 255, 255, 255, 255],
    body: { opcode: "SAVE_XMM128_FAR", register: 15, displacement: 4294967295 }, slots: 3 },
  { bytes: [7, 10], body: { opcode: "PUSH_MACHFRAME", size: 40 }, slots: 1 },
  { bytes: [7, 0x1a], body: { opcode: "PUSH_MACHFRAME", size: 48 }, slots: 1 }
];

for (const { bytes, body, slots } of operations) {
  void test(`decodes ${body.opcode} operands ${bytes.join(",")}`, () => {
    const issues: string[] = [];
    assert.deepEqual(decodeAmd64UnwindOperation(viewOf([0, 0, ...bytes]), 1, issues),
      { codeOffset: 7, ...body });
    assert.equal(amd64UnwindOperationSlots(bytes[1]! & 15, bytes[1]! >>> 4), slots);
    assert.deepEqual(issues, []);
  });
}

for (const byte of [6, 7, 11, 15, 0x21, 0x13, 0x2a]) {
  void test(`rejects reserved opcode or OpInfo ${byte}`, () => {
    const issues: string[] = [];
    assert.equal(decodeAmd64UnwindOperation(viewOf([1, byte, 0, 0, 0, 0]), 0, issues), null);
    assert.match(issues.join(" "), /unknown or reserved|reserved OpInfo/);
  });
}

for (const index of [-1, 0.5, Infinity, NaN, 1]) {
  void test(`rejects operation index ${index}`, () => {
    const issues: string[] = [];
    assert.equal(decodeAmd64UnwindOperation(viewOf([1, 0]), index, issues), null);
    assert.deepEqual(issues, ["AMD64 unwind operation header is out of bounds."]);
  });
}

for (const byte of [1, 0x11, 4, 5, 8, 9]) {
  void test(`bounds operands by the supplied view for opcode ${byte}`, () => {
    const bytes = Uint8Array.from([0, 0, 7, byte, 255, 255, 255, 255]);
    const issues: string[] = [];
    assert.equal(decodeAmd64UnwindOperation(new DataView(bytes.buffer, 2, 2), 0, issues), null);
    assert.deepEqual(issues, ["AMD64 unwind operation operands are truncated."]);
  });
}

void test("rejects an incomplete two-byte operation header", () => {
  const issues: string[] = [];
  assert.equal(decodeAmd64UnwindOperation(viewOf([7]), 0, issues), null);
  assert.match(issues[0]!, /header is out of bounds/);
});
