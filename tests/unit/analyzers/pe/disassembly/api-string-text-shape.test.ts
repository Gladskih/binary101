"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  hasImplausibleWideTextShape,
  hasOnlyReasonableText,
  isReasonableAsciiByte
} from "../../../../../analyzers/pe/disassembly/api-string-text-shape.js";

const textFromCodeUnits = (codeUnits: readonly number[]): string =>
  String.fromCharCode(...codeUnits);

const codeUnitsFromText = (text: string): number[] =>
  [...text].map(character => character.charCodeAt(0));

const sequentialLookupTableText = (): string => {
  const codeUnits: number[] = [];
  for (let codeUnit = 0xa9f8; codeUnit <= 0xac00; codeUnit += 8) {
    codeUnits.push(codeUnit);
  }
  return textFromCodeUnits(codeUnits);
};

void test("isReasonableAsciiByte accepts graphic ASCII and text controls", () => {
  assert.equal(isReasonableAsciiByte(0x41), true);
  assert.equal(isReasonableAsciiByte(0x0a), true);
  assert.equal(isReasonableAsciiByte(0x1b), false);
});

void test("hasOnlyReasonableText rejects replacement and C1 control characters", () => {
  assert.equal(hasOnlyReasonableText("plain text"), true);
  assert.equal(hasOnlyReasonableText("bad\u007ftext"), false);
  assert.equal(hasOnlyReasonableText("bad\ufffdtext"), false);
  assert.equal(hasOnlyReasonableText("bad\u0093text"), false);
  assert.equal(hasOnlyReasonableText(""), false);
});

void test("hasImplausibleWideTextShape rejects ASCII byte pairs read as UTF-16", () => {
  // These UTF-16 code units are the narrow bytes for "bad exception" paired little-endian.
  assert.equal(hasImplausibleWideTextShape(textFromCodeUnits([
    0x6162, 0x2064, 0x7865, 0x6563, 0x7470, 0x6f69, 0x006e
  ])), true);
});

void test("hasImplausibleWideTextShape rejects alternating Han-like and ASCII table data", () => {
  assert.equal(hasImplausibleWideTextShape(textFromCodeUnits([
    0x6180, 0x0041, 0x6288, 0x0041, 0x0043
  ])), true);
});

void test("hasImplausibleWideTextShape rejects mixed-script binary noise", () => {
  assert.equal(hasImplausibleWideTextShape(textFromCodeUnits([
    0x0d8b, 0x128c, 0x0059, 0x8b64, 0x8b09, 0xe203, 0x8b0c, 0x0442
  ])), true);
});

void test("hasImplausibleWideTextShape rejects private-use and CJK-extension noise", () => {
  assert.equal(hasImplausibleWideTextShape("\ue000private"), true);
  assert.equal(hasImplausibleWideTextShape(textFromCodeUnits([
    0x3400, 0x3401, 0x3402, 0x3403, 0x3404, 0x3405, 0x3406, 0x3407
  ])), true);
  assert.equal(hasImplausibleWideTextShape(textFromCodeUnits([
    0x3400, 0x4e00, 0xac00, 0x2b00, 0x3401, 0x4e01, 0xac01, 0x2b01
  ])), true);
});

void test("hasImplausibleWideTextShape rejects sequential Unicode lookup tables", () => {
  assert.equal(hasImplausibleWideTextShape(sequentialLookupTableText()), true);
});

void test("hasImplausibleWideTextShape keeps compact ASCII-pair text without word spaces", () => {
  assert.equal(hasImplausibleWideTextShape(textFromCodeUnits([
    0x4142, 0x4344, 0x4546, 0x4748, 0x494a, 0x4b4c
  ])), false);
});

void test("hasImplausibleWideTextShape keeps normal UTF-16 strings", () => {
  assert.equal(hasImplausibleWideTextShape("mscoree.dll"), false);
  assert.equal(hasImplausibleWideTextShape(textFromCodeUnits([
    // Japanese text with Han and Katakana should not be treated as mixed-script noise.
    ...codeUnitsFromText("\u65e5\u672c\u8a9e\u30c6\u30b9\u30c8")
  ])), false);
});
