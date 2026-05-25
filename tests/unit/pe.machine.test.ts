"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodePeMachine,
  formatPeMachine,
  getCanonicalPeMachine,
  isReadyToRunOsOverriddenMachine
} from "../../analyzers/pe/machine.js";

void test("decodePeMachine recognizes Linux ReadyToRun x64 machine values", () => {
  // .NET ReadyToRun encodes the target OS by XOR:
  // IMAGE_FILE_MACHINE_AMD64 0x8664 ^ Linux override 0x7B79 = 0xFD1D.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/pedecoder.h
  const decoded = decodePeMachine(0xfd1d);

  assert.equal(decoded.machine, 0x8664);
  assert.equal(decoded.machineName, "x86-64 (AMD64)");
  assert.equal(decoded.os, "Linux");
  assert.equal(getCanonicalPeMachine(0xfd1d), 0x8664);
  assert.equal(isReadyToRunOsOverriddenMachine(0xfd1d), true);
  assert.equal(formatPeMachine(0xfd1d), "x86-64 (AMD64) ReadyToRun for Linux");
});

void test("decodePeMachine preserves ordinary PE machine values", () => {
  const decoded = decodePeMachine(0x8664);

  assert.equal(decoded.machine, 0x8664);
  assert.equal(decoded.machineName, "x86-64 (AMD64)");
  assert.equal(decoded.os, null);
  assert.equal(isReadyToRunOsOverriddenMachine(0x8664), false);
});
