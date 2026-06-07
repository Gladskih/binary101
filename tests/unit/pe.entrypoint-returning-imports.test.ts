"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  isKnownReturningImport
} from "../../analyzers/pe/disassembly/entrypoint/returning-imports.js";

void test("isKnownReturningImport accepts documented returning Kernel32 query APIs", () => {
  assert.equal(isKnownReturningImport("KERNEL32.dll!GetSystemTimeAsFileTime"), true);
  assert.equal(isKnownReturningImport("KernelBase.dll!GetTickCount64"), true);
  assert.equal(isKnownReturningImport("KERNEL32.dll!GetStdHandle"), true);
  assert.equal(isKnownReturningImport("KERNEL32.dll!WriteFile"), true);
  assert.equal(
    isKnownReturningImport("api-ms-win-core-processthreads-l1-1-0.dll!GetCurrentProcessId"),
    true
  );
  assert.equal(isKnownReturningImport("KERNEL32.dll!_WriteFile@20"), true);
});

void test(
  "isKnownReturningImport rejects unknown DLLs, unknown functions, and malformed labels",
  () => {
    assert.equal(isKnownReturningImport("KERNEL32.dll!ExitProcess"), false);
    assert.equal(isKnownReturningImport("USER32.dll!GetTickCount64"), false);
    assert.equal(isKnownReturningImport("GetSystemTimeAsFileTime"), false);
  }
);
