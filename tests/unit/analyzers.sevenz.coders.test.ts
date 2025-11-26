"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CODER_NAMES,
  CODER_ARCH_HINTS,
  normalizeMethodId,
  describeCoderId,
  parseCoderProperties
} from "../../dist/analyzers/sevenz/coders.js";

test("normalizeMethodId handles nullish and upper-case ids", () => {
  assert.equal(normalizeMethodId(null), "");
  assert.equal(normalizeMethodId(undefined), "");
  assert.equal(normalizeMethodId("03"), "03");
  assert.equal(normalizeMethodId("03030103"), "03030103");
});

test("describeCoderId returns known names or hex fallback", () => {
  assert.equal(describeCoderId("03"), CODER_NAMES["03"]);
  assert.equal(describeCoderId("unknown"), "0xunknown");
});

test("parseCoderProperties decodes LZMA, LZMA2, Delta and BCJ props", () => {
  const lzma = parseCoderProperties("030101", Uint8Array.from([0x5d, 0x00, 0x00, 0x04, 0x00]));
  assert.deepEqual(lzma, { dictSize: 0x00040000, lc: 3, lp: 0, pb: 2 });

  const lzma2Prop = 0x20;
  const lzma2 = parseCoderProperties("21", Uint8Array.from([lzma2Prop]));
  const base = (lzma2Prop & 1) + 2;
  const expectedDictSize = base << (Math.floor(lzma2Prop / 2) + 11);
  assert.deepEqual(lzma2, { dictSize: expectedDictSize });

  const delta = parseCoderProperties("03", Uint8Array.from([0x02]));
  assert.deepEqual(delta, { distance: 3 });

  const bcjArch = parseCoderProperties("03030103", Uint8Array.from([]));
  assert.deepEqual(bcjArch, { filterType: CODER_ARCH_HINTS["03030103"] });

  const bcjOffset = parseCoderProperties("03030103", Uint8Array.from([0x04, 0x00, 0x00, 0x00]));
  assert.deepEqual(bcjOffset, { filterType: CODER_ARCH_HINTS["03030103"], startOffset: 4 });
});

test("parseCoderProperties returns null for unsupported methods", () => {
  assert.equal(parseCoderProperties("ff", Uint8Array.from([0x01])), null);
});
