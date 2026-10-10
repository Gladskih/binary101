import assert from "node:assert/strict";
import { test } from "node:test";
import { parseReadyToRunDebug } from "../../../../../analyzers/pe/clr/ready-to-run-debug.js";
import { debugSection, nibbleIntegers } from "../../../../helpers/ready-to-run-debug-fixture.js";

void test("reads both independently bounded payloads in an indexed method", () => {
  const warnings = new Set<string>();
  const bytes = debugSection(nibbleIntegers([1, 2, 3, 16]), nibbleIntegers([1, 0, 3, 4, 0, 1]));

  assert.deepEqual(parseReadyToRunDebug(bytes, 10, 0x8664, warnings), [{ runtimeFunctionIndex: 0,
    bounds: [{ nativeOffset: 2, ilOffset: 0, source: 16 }], variables: [{ startOffset: 0,
      endOffset: 3, variableNumber: 0, location: { kind: "register", register: 1 } }] }]);
  assert.deepEqual([...warnings], []);
});

void test("accepts empty debug payloads and absent NativeArray indices", () => {
  const warnings = new Set<string>();

  assert.deepEqual(parseReadyToRunDebug(debugSection(new Uint8Array(), new Uint8Array()),
    16, undefined, warnings), [{ runtimeFunctionIndex: 0, bounds: [], variables: [] }]);
  assert.deepEqual(parseReadyToRunDebug(Uint8Array.of(8, 1, 8), 16, undefined, warnings), []);
  assert.deepEqual([...warnings], []);
});

void test("rejects invalid lookbacks, NativeArray indexes and truncated payloads visibly", () => {
  const warnings = new Set<string>();

  assert.deepEqual(parseReadyToRunDebug(Uint8Array.of(8, 1, 0, 10), 16, undefined, warnings), []);
  assert.deepEqual(parseReadyToRunDebug(Uint8Array.of(8), 16, undefined, warnings), []);
  assert.deepEqual(parseReadyToRunDebug(Uint8Array.of(8, 1, 0, 0, 0x77),
    16, undefined, warnings), [{ runtimeFunctionIndex: 0, bounds: [], variables: [] }]);
  assert.match([...warnings].join(), /lookback/);
  assert.match([...warnings].join(), /index/);
  assert.match([...warnings].join(), /truncated/);
  assert.ok(warnings.has("DebugInfo payload is truncated."));
});

void test("resolves shared backward payloads without interpreting data as a new header", () => {
  // Index block points past an earlier [lengths=0] payload at offset 2; leaf at 3, lookback at 4.
  const warnings = new Set<string>();

  assert.deepEqual(parseReadyToRunDebug(Uint8Array.of(8, 2, 0, 0, 4), 16,
    undefined, warnings), [{ runtimeFunctionIndex: 0, bounds: [], variables: [] }]);
  assert.deepEqual([...warnings], []);
});

void test("reuses decoded payload arrays for distinct runtime functions", () => {
  const warnings = new Set<string>();
  const methods = parseReadyToRunDebug(Uint8Array.of(16, 1, 2, 2, 2, 30, 0, 0, 2),
    16, undefined, warnings);

  assert.equal(methods.length, 2);
  assert.equal(methods[0]?.bounds, methods[1]?.bounds);
  assert.equal(methods[0]?.variables, methods[1]?.variables);
  assert.deepEqual([...warnings], []);
});

void test("allows a shared payload at section offset zero", () => {
  const warnings = new Set<string>();

  assert.deepEqual(parseReadyToRunDebug(Uint8Array.of(8, 1, 0, 6), 16,
    undefined, warnings), [{ runtimeFunctionIndex: 0, bounds: [], variables: [] }]);
  assert.deepEqual([...warnings], []);
});
