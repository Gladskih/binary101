"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodeCallingConvention,
  decodeCharacterSet,
  isVariadicConvention,
  mappingSupportsLastError
} from "../../../../scripts/winapi-metadata/pinvoke-flags.js";

void test("decodeCallingConvention decodes ECMA-335 ImplMap call-convention bits", () => {
  assert.equal(decodeCallingConvention(0x0100), "winapi");
  assert.equal(decodeCallingConvention(0x0200), "cdecl");
  assert.equal(decodeCallingConvention(0x0300), "stdcall");
  assert.equal(isVariadicConvention(0x0200), true);
  assert.equal(isVariadicConvention(0x0100), false);
});

void test("decodeCharacterSet and mappingSupportsLastError decode ImplMap flags", () => {
  assert.equal(decodeCharacterSet(0x0002), "ansi");
  assert.equal(decodeCharacterSet(0x0004), "unicode");
  assert.equal(decodeCharacterSet(0x0006), "auto");
  assert.equal(mappingSupportsLastError(0x0040), true);
  assert.equal(mappingSupportsLastError(0), false);
});
