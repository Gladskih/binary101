import assert from "node:assert/strict";
import { test } from "node:test";
import { readyToRunPointerSize, readyToRunRuntimeFunctionSize } from
  "../../../../../analyzers/pe/clr/ready-to-run-target.js";

void test("uses target architecture rather than optional-header bitness", () => {
  // readyToRun.h / ReadyToRunReader: x86 and ARM32 cells are four bytes.
  assert.equal(readyToRunPointerSize(0x14c), 4);
  assert.equal(readyToRunPointerSize(0x1c4), 4);
  assert.equal(readyToRunPointerSize(0x8664), 8);
  assert.equal(readyToRunPointerSize(0xaa64), 8);
  assert.equal(readyToRunPointerSize(0x6264), 8);
  assert.equal(readyToRunPointerSize(0x5064), 8);
  assert.equal(readyToRunRuntimeFunctionSize(0x8664), 12);
  assert.equal(readyToRunRuntimeFunctionSize(0xaa64), 8);
  assert.equal(readyToRunRuntimeFunctionSize(0x14c), 8);
});

void test("decodes ReadyToRun OS overrides and leaves unknown targets unresolved", () => {
  // pedecoder.h: Linux Machine is architecture XOR 0x7b79.
  assert.equal(readyToRunPointerSize(0x8664 ^ 0x7b79), 8);
  assert.equal(readyToRunRuntimeFunctionSize(0x8664 ^ 0x7b79), 12);
  assert.equal(readyToRunPointerSize(undefined), undefined);
  assert.equal(readyToRunPointerSize(0xffff), undefined);
  assert.equal(readyToRunRuntimeFunctionSize(undefined), undefined);
  assert.equal(readyToRunRuntimeFunctionSize(0xffff), undefined);
});
