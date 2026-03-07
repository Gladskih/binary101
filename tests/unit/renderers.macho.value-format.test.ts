"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { formatByteSize, formatHex, formatList } from "../../renderers/macho/value-format.js";

void test("Mach-O value formatters preserve 64-bit numbers", () => {
  assert.equal(formatHex(0x1_0000_0000), "0x100000000");
  assert.match(formatByteSize(0x1_0000_0000), /4294967296 bytes/);
});

void test("Mach-O list formatter renders populated and empty lists", () => {
  assert.equal(formatList(["__TEXT", "__DATA"]), "__TEXT, __DATA");
  assert.match(formatList([]), /class="muted"/);
});
