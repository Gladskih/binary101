import assert from "node:assert/strict";
import { test } from "node:test";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { readDwarfExpressionOperands } from "../../../../analyzers/dwarf/expression-operands.js";
import { MockFile } from "../../../helpers/mock-file.js";

const readOperands = async (opcode: number, bytes: number[], issues: string[] = []) => {
  const file = new MockFile(Uint8Array.from(bytes));
  return readDwarfExpressionOperands(new DwarfCursor(file,
    { name: "expression", offset: 0, size: file.size, compressed: false },
    0, file.size, true, issues), opcode,
  { version: 5, format: 32, addressSize: 8, stringOffsetsBase: null });
};

// Operand layouts are encoded independently from DWARF 5 7.7.1.
const examples = [
  { name: "signed fixed", opcode: 0x09, bytes: [0xff], expected: [-1n] },
  { name: "unsigned LEB", opcode: 0x10, bytes: [0x80, 1], expected: [128n] },
  { name: "base register", opcode: 0x70, bytes: [0x7f], expected: [-1n] },
  { name: "section offset", opcode: 0x9a, bytes: [1, 0, 0, 0], expected: [1n] },
  { name: "implicit value", opcode: 0x9e, bytes: [2, 3, 4], expected: [Uint8Array.of(3, 4)] },
  { name: "typed value", opcode: 0xa4, bytes: [1, 2, 3, 4], expected: [1n, Uint8Array.of(3, 4)] },
  { name: "nested value", opcode: 0xa3, bytes: [1, 0x50], expected: [{ offset: 1, size: 1 }] },
  { name: "no operands", opcode: 0x50, bytes: [], expected: [] },
  { name: "stack operation", opcode: 0x12, bytes: [], expected: [] }
];
for (const example of examples) {
  void test(`expression operands decode ${example.name}`, async () => {
    assert.deepEqual(await readOperands(example.opcode, example.bytes), example.expected);
  });
}
const truncated = [
  { name: "fixed", opcode: 0x0a, bytes: [1] },
  { name: "variable", opcode: 0x10, bytes: [0x80] },
  { name: "block length", opcode: 0x9e, bytes: [] },
  { name: "block payload", opcode: 0x9e, bytes: [2, 1] },
  { name: "typed block", opcode: 0xa4, bytes: [1] },
  { name: "nested payload", opcode: 0xa3, bytes: [2, 1] },
  { name: "unknown", opcode: 0xff, bytes: [] }
];
for (const example of truncated) {
  void test(`expression operands reject truncated ${example.name}`, async () => {
    const issues: string[] = [];

    assert.equal(await readOperands(example.opcode, example.bytes, issues), null);
    assert.equal(issues.length, 1);
  });
}
