import assert from "node:assert/strict";
import { test } from "node:test";
import { dwarfCodeRanges, dwarfCodeSize } from "../../../../analyzers/dwarf/code-ranges.js";
import type { DwarfAttribute, DwarfDie } from "../../../../analyzers/dwarf/types.js";

const dieWith = (attributes: DwarfAttribute[]): DwarfDie => ({
  offset: 0, tag: 0x2e, parentOffset: null, attributes
});
const pcDie = (form: number, high: bigint, low = 0x1000n): DwarfDie => dieWith([
  { name: 0x11, form: 0x01, value: { kind: "unsigned", value: low } },
  { name: 0x12, form, value: { kind: "unsigned", value: high } }
]); // DW_AT_low_pc/high_pc: DWARF 5 2.17.2.

void test("code ranges distinguish constant high_pc from absolute addresses", () => {
  assert.deepEqual(dwarfCodeRanges(pcDie(0x06, 6n)), [{ start: 0x1000n, end: 0x1006n }]);
  assert.equal(dwarfCodeSize(pcDie(0x01, 0x1006n)), 6n);
  assert.equal(dwarfCodeSize(pcDie(0x06, 0n)), 0n);
  assert.equal(dwarfCodeSize(dieWith([])), null);
  assert.equal(dwarfCodeSize(pcDie(0x01, 0xfffn)), null);
  assert.equal(dwarfCodeSize(pcDie(0x06, -1n)), null);
  assert.equal(dwarfCodeSize(pcDie(0x17, 6n)), null);
  assert.equal(dwarfCodeSize(pcDie(0x06, 6n, -1n)), null);
});

void test("unresolved split ranges cannot produce a misleading partial code size", () => {
  const die = dieWith([{ name: 0x55, form: 0x17, value: { kind: "ranges",
    entries: [{ start: 0x1000n, end: 0x1004n }, { kind: "unresolved" }] } }]);
  assert.deepEqual(dwarfCodeRanges(die), [{ start: 0x1000n, end: 0x1004n }]);
  assert.equal(dwarfCodeSize(die), null);
});

void test("code size counts overlapping and repeated ranges only once", () => {
  const die = dieWith([{ name: 0x55, form: 0x17, value: { kind: "ranges", entries: [
    { start: 9n, end: 12n }, { start: 0n, end: 8n }, { start: 4n, end: 6n },
    { start: 5n, end: 10n }, { start: 14n, end: 16n }
  ] } }]);

  assert.equal(dwarfCodeSize(die), 14n);
  assert.equal(dwarfCodeRanges(die).length, 5);
  assert.equal(dwarfCodeSize(dieWith([{ name: 0x55, form: 0x17,
    value: { kind: "ranges", entries: [] } }])), null);
  assert.equal(dwarfCodeSize(dieWith([{ name: 0x12, form: 0x06,
    value: { kind: "string", value: "invalid" } }])), null);
});
