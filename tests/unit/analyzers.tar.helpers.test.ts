"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  describeFormat,
  formatModeSymbolic,
  formatModeOctal,
  toSafeNumber,
  align512,
  isZeroBlock,
  combineNameParts,
  parseBase256Number,
  parseOctalNumber,
  parseTarNumber
} from "../../analyzers/tar/helpers.js";

void test("describeFormat covers different TAR variants", () => {
  assert.deepStrictEqual(describeFormat("ustar", "00"), {
    magic: "ustar",
    version: "00",
    label: "POSIX ustar (1988)",
    kind: "posix",
  });

  assert.deepStrictEqual(describeFormat("ustar", ""), {
    magic: "ustar",
    version: "",
    label: "POSIX ustar",
    kind: "posix",
  });
  
  assert.deepStrictEqual(describeFormat("ustar ", " "), {
    magic: "ustar ",
    version: " ",
    label: "GNU tar (ustar)",
    kind: "gnu",
  });

  assert.deepStrictEqual(describeFormat("ustar", " "), {
    magic: "ustar",
    version: " ",
    label: "ustar variant",
    kind: "posix",
  });

  assert.deepStrictEqual(describeFormat("", ""), {
    magic: "",
    version: "",
    label: "Legacy V7 header (no magic)",
    kind: "legacy",
  });
});

void test("formatModeSymbolic", () => {
  assert.strictEqual(formatModeSymbolic(0o755), "rwxr-xr-x");
  assert.strictEqual(formatModeSymbolic(0o644), "rw-r--r--");
  assert.strictEqual(formatModeSymbolic(0o4000 | 0o755), "rwsr-xr-x");
  assert.strictEqual(formatModeSymbolic(0o2000 | 0o755), "rwxr-sr-x");
  assert.strictEqual(formatModeSymbolic(0o1000 | 0o755), "rwxr-xr-t");
  assert.strictEqual(formatModeSymbolic(0o4000 | 0o644), "rwSr--r--");
  assert.strictEqual(formatModeSymbolic(0o2000 | 0o644), "rw-r-Sr--");
  assert.strictEqual(formatModeSymbolic(0o1000 | 0o644), "rw-r--r-T");
  assert.strictEqual(formatModeSymbolic(null), null);
});

void test("formatModeOctal", () => {
  assert.strictEqual(formatModeOctal(0o755), "000755");
  assert.strictEqual(formatModeOctal(0o644), "000644");
  assert.strictEqual(formatModeOctal(null), null);
});

void test("toSafeNumber", () => {
  assert.strictEqual(toSafeNumber(123), 123);
  assert.strictEqual(toSafeNumber(BigInt(123)), 123);
  assert.strictEqual(toSafeNumber(BigInt(Number.MAX_SAFE_INTEGER) + 1n), null);
  assert.strictEqual(toSafeNumber(BigInt(Number.MIN_SAFE_INTEGER) - 1n), null);
  assert.strictEqual(toSafeNumber("123"), null);
});

void test("align512", () => {
  assert.strictEqual(align512(0), 0);
  assert.strictEqual(align512(1), 512);
  assert.strictEqual(align512(512), 512);
  assert.strictEqual(align512(513), 1024);
});

void test("isZeroBlock", () => {
  assert.strictEqual(isZeroBlock(new Uint8Array(512).fill(0)), true);
  const notZero = new Uint8Array(512).fill(0);
  notZero[10] = 1;
  assert.strictEqual(isZeroBlock(notZero), false);
});

void test("combineNameParts", () => {
  assert.strictEqual(combineNameParts("a", "b"), "a/b");
  assert.strictEqual(combineNameParts("a/", "b"), "a/b");
  assert.strictEqual(combineNameParts("a//", "b"), "a/b");
  assert.strictEqual(combineNameParts("", "b"), "b");
  assert.strictEqual(combineNameParts("a", ""), "a");
  assert.strictEqual(combineNameParts("", ""), "");
});

void test("parseTarNumber", () => {
    const octal = new TextEncoder().encode("123\0");
    assert.strictEqual(parseTarNumber(new Uint8Array(octal), 0, octal.length), 83);
    
    const base256 = [0x80, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5];
    assert.strictEqual(parseTarNumber(new Uint8Array(base256), 0, base256.length), 4328719365); // Corrected expected value

    assert.strictEqual(parseTarNumber(new Uint8Array(), 0, 0), null);
});

void test("parseOctalNumber", () => {
    assert.strictEqual(parseOctalNumber(new TextEncoder().encode("123\0")), 83);
    assert.strictEqual(parseOctalNumber(new TextEncoder().encode(" 123 \0")), 83);
    assert.strictEqual(parseOctalNumber(new TextEncoder().encode(" \0")), null);
    assert.strictEqual(parseOctalNumber(new TextEncoder().encode("abc")), null);

});

void test("parseBase256Number", () => {
    const base256 = [0x80, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5];
    assert.strictEqual(parseBase256Number(new Uint8Array(base256)), 4328719365); // Corrected expected value
    assert.strictEqual(parseBase256Number(new Uint8Array()), null);
});