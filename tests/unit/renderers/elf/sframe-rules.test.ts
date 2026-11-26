import assert from "node:assert/strict";
import { test } from "node:test";
import { sframeRules } from "../../../../renderers/elf/sframe-rules.js";

const header = (abi: number, fixedRaOffset = 0, fixedFpOffset = 0) => ({
  abi, fixedRaOffset, fixedFpOffset, auxSize: 0, functionCount: 1,
  rowCount: 1, rowBytes: 0, functionOffset: 0, rowOffset: 0
});

const row = (words: number[], info = 1) => ({ words, info, functionIndex: 0, pcOffset: 0 });

void test("uses AMD64 fixed RA, per-row FP and CFA base", () => {
  assert.deepEqual(sframeRules(row([16, -16], 4), header(3, -8), 3, 0),
    ["FP + 16", "[CFA − 16]", "[CFA − 8]"]);
  assert.deepEqual(sframeRules(row([8]), header(3, -8, -16), 3, 0),
    ["SP + 8", "[CFA − 16]", "[CFA − 8]"]);
});

void test("decodes flexible AMD64 recovery with a padding word for the default RA", () => {
  // DWARF r6 is RBP. 0x33 encodes register-mode r6 with dereference, §3.2.
  assert.deepEqual(sframeRules(row([0x33, -8, 0, 0x33, 0]), header(3, -8), 3, 1),
    ["[r6 − 8]", "[r6 + 0]", "[CFA − 8]"]);
  assert.deepEqual(sframeRules(row([0x31, 0, 2, -24]), header(3, -8, -16), 3, 1),
    ["r6 + 0", "[CFA − 16]", "[CFA − 24]"]);
  assert.deepEqual(sframeRules(row([0x35, -8, 2]), header(3), 3, 1), ["—", "—", "—"]);
});

void test("decodes the s390x CFA scaling and v2 register encoding", () => {
  // v2 packs r16 as (16 << 1) | 1. A zero RA slot is unspecified on s390x.
  assert.deepEqual(sframeRules(row([1, 0, 33]), header(4), 2, 0),
    ["SP + 168", "r16", "—"]);
  assert.deepEqual(sframeRules(row([1, 0, -16]), header(4), 3, 0),
    ["SP + 168", "[CFA − 16]", "—"]);
  // 0x83 is (16 << 3) | 3, encoded in an 8-bit control word.
  assert.deepEqual(sframeRules(row([-125, 0, 0, 2, -16]), header(4), 3, 1),
    ["[r16 + 160]", "[CFA − 16]", "—"]);
});

void test("distinguishes undefined RA and unknown recovery encodings", () => {
  assert.deepEqual(sframeRules(row([]), header(3, -8), 3, 0), ["—", "—", "Undefined"]);
  assert.deepEqual(sframeRules(row([]), header(3, -8), 1, 0), ["—", "—", "—"]);
  assert.deepEqual(sframeRules(row([]), header(3, -8), 3, 1), ["—", "—", "Undefined"]);
  assert.deepEqual(sframeRules(row([16]), header(255), 3, 0), ["—", "—", "—"]);
  assert.deepEqual(sframeRules(row([16]), header(3), 3, 2), ["—", "—", "—"]);
});
