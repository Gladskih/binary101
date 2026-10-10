import assert from "node:assert/strict";
import { test } from "node:test";
import { readDebugVariables } from "../../../../../analyzers/pe/clr/ready-to-run-debug-variables.js";
import { nibbleIntegers } from "../../../../helpers/ready-to-run-debug-fixture.js";

void test("decodes all eleven cordebuginfo variable location variants and implicit arguments", () => {
  // count, (start, length, variable+4, location, operands), repeated for every location tag.
  const bytes = nibbleIntegers([11,
    0, 2, 0, 0, 1, 0, 2, 1, 1, 2, 0, 2, 2, 2, 3,
    0, 2, 3, 3, 4, 7, 0, 2, 4, 4, 5, 6, 0, 2, 5, 5, 1, 2,
    0, 2, 6, 6, 1, 2, 7, 0, 2, 7, 7, 7, 2, 1, 0, 2, 8, 8, 2, 6,
    0, 2, 9, 9, 3, 0, 2, 10, 10, 8]);
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

  assert.deepEqual(readDebugVariables(nibbleIntegers([1, 4, 5, 4, 3, 2, 7]),
    0x14c ^ 0x7b79, warnings), [{ startOffset: 4, endOffset: 9, variableNumber: 0,
    location: { kind: "stack", baseRegister: 2, offset: -12 } }]);
  assert.deepEqual([...warnings], []);
});

void test("keeps complete variable records before unknown locations and truncated operands", () => {
  const warnings = new Set<string>();

  assert.equal(readDebugVariables(nibbleIntegers([2, 0, 1, 4, 0, 1, 0, 1, 4, 11]),
    undefined, warnings).length, 1);
  assert.deepEqual(readDebugVariables(nibbleIntegers([1, 0, 1, 4, 6]),
    undefined, warnings), []);
  assert.match([...warnings].join(), /location/);
  assert.match([...warnings].join(), /truncated/);
});

void test("rejects overflowing variable lifetimes", () => {
  const warnings = new Set<string>();

  assert.deepEqual(readDebugVariables(nibbleIntegers([1, 0xffffffff, 1, 4, 0, 1]),
    undefined, warnings), []);
  assert.match([...warnings].join(), /overflow/);
});

void test("reports an unknown target instead of guessing stack-offset scaling", () => {
  const warnings = new Set<string>();

  assert.deepEqual(readDebugVariables(nibbleIntegers([1, 0, 1, 4, 3, 2, 7]),
    undefined, warnings), []);
  assert.match([...warnings].join(), /target machine/);
});

void test("accepts the largest representable native lifetime endpoint", () => {
  const warnings = new Set<string>();

  assert.equal(readDebugVariables(nibbleIntegers([1, 0xffffffff, 0, 4, 0, 1]),
    0x8664, warnings)[0]?.endOffset, 0xffffffff);
  assert.deepEqual([...warnings], []);
});
