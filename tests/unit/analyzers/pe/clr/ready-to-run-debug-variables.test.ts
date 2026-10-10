import assert from "node:assert/strict";
import { test } from "node:test";
import { readDebugVariables } from "../../../../../analyzers/pe/clr/ready-to-run-debug-variables.js";
import { debugVariables, nibbleIntegers } from "../../../../helpers/ready-to-run-debug-fixture.js";

void test("decodes all eleven cordebuginfo variable location variants and implicit arguments", () => {
  // Tag and operand meanings follow VarLoc in the runtime's cordebuginfo.h.
  const bytes = debugVariables([
    { start: 0, length: 2, variableNumber: -4, location: 0, operands: [1] },
    { start: 0, length: 2, variableNumber: -3, location: 1, operands: [2] },
    { start: 0, length: 2, variableNumber: -2, location: 2, operands: [3] },
    { start: 0, length: 2, variableNumber: -1, location: 3, operands: [4, 7] },
    { start: 0, length: 2, variableNumber: 0, location: 4, operands: [5, 6] },
    { start: 0, length: 2, variableNumber: 1, location: 5, operands: [1, 2] },
    { start: 0, length: 2, variableNumber: 2, location: 6, operands: [1, 2, 7] },
    { start: 0, length: 2, variableNumber: 3, location: 7, operands: [7, 2, 1] },
    { start: 0, length: 2, variableNumber: 4, location: 8, operands: [2, 6] },
    { start: 0, length: 2, variableNumber: 5, location: 9, operands: [3] },
    { start: 0, length: 2, variableNumber: 6, location: 10, operands: [8] }
  ]);
  const warnings = new Set<string>();

  assert.deepEqual(readDebugVariables(bytes, 0x8664, warnings).map(entry => entry.location), [
    { kind: "register", register: 1 }, { kind: "register-byref", register: 2 },
    { kind: "fp-register", register: 3 }, { kind: "stack", baseRegister: 4, offset: -3 },
    { kind: "stack-byref", baseRegister: 5, offset: 3 },
    { kind: "register-pair", register1: 1, register2: 2 },
    { kind: "register-stack", register: 1, baseRegister: 2, offset: -3 },
    { kind: "stack-register", offset: -3, baseRegister: 2, register: 1 },
    { kind: "stack-pair", baseRegister: 2, offset: 3 },
    { kind: "fp-stack", index: 3 }, { kind: "varargs", offset: 8 }
  ]);
  assert.equal(readDebugVariables(bytes, 0x8664, warnings)[0]?.variableNumber, -4);
  assert.deepEqual([...warnings], []);
});

void test("scales x86 stack offsets and decodes OS-overridden target machine IDs", () => {
  const warnings = new Set<string>();

  // IMAGE_FILE_MACHINE_I386 XOR .NET's Linux override identifies the target; signed slot
  // displacement -3 is scaled by the 4-byte x86 stack slot size.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/pedecoder.h
  assert.deepEqual(readDebugVariables(debugVariables([{ start: 4, length: 5, variableNumber: 0,
    location: 3, operands: [2, 7] }]),
    0x14c ^ 0x7b79, warnings), [{ startOffset: 4, endOffset: 9, variableNumber: 0,
    location: { kind: "stack", baseRegister: 2, offset: -12 } }]);
  assert.deepEqual([...warnings], []);
});

void test("keeps complete variable records before unknown locations and truncated operands", () => {
  const warnings = new Set<string>();

  // Unknown tag 11 follows one complete register record; the second record then has no register.
  assert.equal(readDebugVariables(nibbleIntegers([2, 0, 1, 4, 0, 1, 0, 1, 4, 11]),
    undefined, warnings).length, 1);
  assert.deepEqual(readDebugVariables(nibbleIntegers([1, 0, 1, 4, 6]),
    undefined, warnings), []);
  assert.match([...warnings].join(), /location/);
  assert.match([...warnings].join(), /truncated/);
});

void test("rejects overflowing variable lifetimes", () => {
  const warnings = new Set<string>();

  assert.deepEqual(readDebugVariables(debugVariables([{ start: 0xffffffff, length: 1,
    variableNumber: 0, location: 0, operands: [1] }]),
    undefined, warnings), []);
  assert.match([...warnings].join(), /overflow/);
});

void test("reports an unknown target instead of guessing stack-offset scaling", () => {
  const warnings = new Set<string>();

  assert.deepEqual(readDebugVariables(debugVariables([{ start: 0, length: 1, variableNumber: 0,
    location: 3, operands: [2, 7] }]),
    undefined, warnings), []);
  assert.match([...warnings].join(), /target machine/);
});

void test("accepts the largest representable native lifetime endpoint", () => {
  const warnings = new Set<string>();

  assert.equal(readDebugVariables(debugVariables([{ start: 0xffffffff, length: 0,
    variableNumber: 0, location: 0, operands: [1] }]),
    0x8664, warnings)[0]?.endOffset, 0xffffffff);
  assert.deepEqual([...warnings], []);
});
