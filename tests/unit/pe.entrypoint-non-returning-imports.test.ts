"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  isKnownNonReturningImport
} from "../../analyzers/pe/disassembly/entrypoint/non-returning-imports.js";

void test("isKnownNonReturningImport accepts known process and CRT terminators", () => {
  assert.equal(isKnownNonReturningImport("KERNEL32.dll!ExitProcess"), true);
  assert.equal(isKnownNonReturningImport("KernelBase.dll!RaiseFailFastException"), true);
  assert.equal(isKnownNonReturningImport("api-ms-win-crt-runtime-l1-1-0.dll!exit"), true);
  assert.equal(isKnownNonReturningImport("ucrtbase.dll!_exit"), true);
  assert.equal(isKnownNonReturningImport("ucrtbase.dll!_Exit"), true);
  assert.equal(isKnownNonReturningImport("ucrtbase.dll!abort"), true);
  assert.equal(isKnownNonReturningImport("ucrtbase.dll!quick_exit"), true);
  assert.equal(isKnownNonReturningImport("ucrtbase.dll!_abort@0"), true);
});

void test("isKnownNonReturningImport rejects returning and malformed labels", () => {
  assert.equal(isKnownNonReturningImport("KERNEL32.dll!GetStdHandle"), false);
  assert.equal(isKnownNonReturningImport("USER32.dll!MessageBoxW"), false);
  assert.equal(isKnownNonReturningImport("api-ms-win-crt-runtime-l1-1-0.dll!_cexit"), false);
  assert.equal(isKnownNonReturningImport("ExitProcess"), false);
});
