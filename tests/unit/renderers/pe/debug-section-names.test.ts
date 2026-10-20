import assert from "node:assert/strict";
import { test } from "node:test";
import { createDebugSectionNameLookup } from "../../../../renderers/pe/debug-section-names.js";
import type { PeSection } from "../../../../analyzers/pe/types.js";
import { inlinePeSectionName } from "../../../../analyzers/pe/sections/name.js";

const section = (name: string, start: number, size: number): PeSection => ({
  name: inlinePeSectionName(name), virtualAddress: start, virtualSize: size,
  sizeOfRawData: size, pointerToRawData: 0, characteristics: 0
});

void test("debug section lookup uses RVA extents and handles unsorted headers and gaps", () => {
  const lookup = createDebugSectionNameLookup([
    section(".data", 0x2000, 16), section(".text", 0x1000, 32)
  ]);

  assert.equal(lookup(0x1000), ".text");
  assert.equal(lookup(0x101f), ".text");
  assert.equal(lookup(0x1020), "(outside sections)");
  assert.equal(lookup(0x2000), ".data");
  assert.equal(lookup(0x200f), ".data");
  assert.equal(lookup(0x2010), "(outside sections)");
  assert.equal(lookup(0), "(outside sections)");
  assert.equal(lookup(Infinity), "(outside sections)");
});

void test("debug section lookup does not lose an enclosing range when sections overlap", () => {
  const lookup = createDebugSectionNameLookup([
    section("outer", 0x1000, 0x100), section("inner", 0x1010, 16)
  ]);

  assert.equal(lookup(0x1010), "outer / inner (overlapping)");
  assert.equal(lookup(0x1050), "outer");
});

void test("debug section lookup handles empty names, empty ranges and raw/virtual extent differences", () => {
  const value = section("", 0x1000, 16);
  value.sizeOfRawData = 32;
  const lookup = createDebugSectionNameLookup([value, section("empty", 0x1008, 0)]);

  assert.equal(lookup(0x101f), "(unnamed section)");
  assert.equal(lookup(0x1008), "(unnamed section)");
  assert.equal(createDebugSectionNameLookup([])(0x1000), "(outside sections)");
});
