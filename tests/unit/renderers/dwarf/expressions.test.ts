import assert from "node:assert/strict";
import { test } from "node:test";
import { dwarfExpressionText } from "../../../../renderers/dwarf/expressions.js";
import type { DwarfExpressionOperation } from "../../../../analyzers/dwarf/types.js";

const operation = (opcode: number, ...operands: DwarfExpressionOperation["operands"]): DwarfExpressionOperation => ({
  opcode, operands, offset: 0
});

void test("location expressions explain registers, frame offsets, pieces, and values", () => {
  assert.equal(dwarfExpressionText([operation(0x55)]), "DWARF register 5");
  assert.equal(dwarfExpressionText([operation(0x73, -8n)]), "register 3 −8 bytes");
  assert.equal(dwarfExpressionText([operation(0x91, 8n)]), "frame base +8 bytes");
  assert.equal(dwarfExpressionText([operation(0x91)]), "frame base ?");
  assert.equal(dwarfExpressionText([operation(0x93, 4n)]), "4-byte piece");
  assert.equal(dwarfExpressionText([operation(0x93)]), "?-byte piece");
  assert.equal(dwarfExpressionText([operation(0x9c), operation(0x9f)]),
    "canonical frame address; value rather than an address");
  assert.equal(dwarfExpressionText([operation(0x03, 0x1000n)]), "static storage address");
  assert.equal(dwarfExpressionText([operation(0x35)]), "literal 5");
});

void test("location expressions retain nested entry values, bytes, constants, and unknown operations", () => {
  assert.equal(dwarfExpressionText([operation(0xa3, [operation(0x50)])]),
    "entry_value (DWARF register 0)");
  assert.equal(dwarfExpressionText([operation(0x10, 7n), operation(0x9e, Uint8Array.of(1, 2))]),
    "constu 7; implicit value 2-byte value");
  assert.equal(dwarfExpressionText([operation(0xff)]), "unknown 0xff");
  assert.equal(dwarfExpressionText([]), "");
});

void test("incomplete expressions disclose truncation instead of claiming a location", () => {
  assert.equal(dwarfExpressionText([{ offset: 0, opcode: 0x03, operands: [], incomplete: true }]),
    "incomplete addr");
});
