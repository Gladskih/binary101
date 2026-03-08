"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  formatByteSize,
  formatFileOffset,
  formatFileRange,
  formatHex,
  formatList
} from "../../renderers/macho/value-format.js";
import { createMachOIncidentalValues } from "../fixtures/macho-incidental-values.js";

void test("Mach-O value formatters preserve 64-bit numbers", () => {
  const largerThanUint32 = 0x1_0000_0000;
  assert.equal(formatHex(largerThanUint32), "0x100000000");
  assert.match(formatByteSize(largerThanUint32), /4294967296 bytes/);
});

void test("Mach-O list formatter renders populated and empty lists", () => {
  assert.equal(formatList(["__TEXT", "__DATA"]), "__TEXT, __DATA");
  assert.match(formatList([]), /class="muted"/);
});

void test("Mach-O file-offset formatters keep fat-slice values absolute", () => {
  const values = createMachOIncidentalValues();
  const sliceOffset = (values.nextUint16() & 0x0ff0) + 0x1000;
  const relativeOffset = (values.nextUint16() & 0x01f0) + 0x200;
  const rangeSize = (values.nextUint8() & 0x3f) + 0x40;

  assert.equal(
    formatFileOffset(sliceOffset, relativeOffset),
    `0x${(sliceOffset + relativeOffset).toString(16)} (0x${relativeOffset.toString(16)} in slice)`
  );
  assert.equal(
    formatFileRange(sliceOffset, relativeOffset, rangeSize),
    `0x${(sliceOffset + relativeOffset).toString(16)} + ${rangeSize} B (${rangeSize} bytes) ` +
      `(0x${relativeOffset.toString(16)} in slice)`
  );
});
