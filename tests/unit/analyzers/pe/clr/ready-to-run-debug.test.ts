import assert from "node:assert/strict";
import { test } from "node:test";
import { parseReadyToRunDebug } from "../../../../../analyzers/pe/clr/ready-to-run-debug.js";
import { debugSection, nibbleIntegers } from "../../../../helpers/ready-to-run-debug-fixture.js";

void test("reads both independently bounded payloads in an indexed method", () => {
  const warnings = new Set<string>();
  const bytes = debugSection(nibbleIntegers([1, 2, 3, 16]), nibbleIntegers([1, 0, 3, 4, 0, 1]));

  // IMAGE_FILE_MACHINE_AMD64 selects unit byte stack slots for any locations in this payload.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
  assert.deepEqual(parseReadyToRunDebug(bytes, 10, 0x8664, warnings), [{ runtimeFunctionIndex: 0,
    bounds: [{ nativeOffset: 2, ilOffset: 0, source: 16 }], variables: [{ startOffset: 0,
      endOffset: 3, variableNumber: 0, location: { kind: "register", register: 1 } }] }]);
  assert.deepEqual([...warnings], []);
});

void test("accepts empty debug payloads and absent NativeArray indices", () => {
  const warnings = new Set<string>();

  assert.deepEqual(parseReadyToRunDebug(debugSection(new Uint8Array(), new Uint8Array()),
    16, undefined, warnings), [{ runtimeFunctionIndex: 0, bounds: [], variables: [] }]);
  // Count=1, one-byte index block; node value 8 marks index zero absent.
  assert.deepEqual(parseReadyToRunDebug(Uint8Array.of(8, 1, 8), 16, undefined, warnings), []);
  assert.deepEqual([...warnings], []);
});

void test("rejects invalid lookbacks, NativeArray indexes and truncated payloads visibly", () => {
  const warnings = new Set<string>();

  // Count=1, one-byte index, leaf zero, then an impossible 10-byte backward distance.
  assert.deepEqual(parseReadyToRunDebug(Uint8Array.of(8, 1, 0, 10), 16, undefined, warnings), []);
  // The count header has no following one-byte index block.
  assert.deepEqual(parseReadyToRunDebug(Uint8Array.of(8), 16, undefined, warnings), []);
  // Inline payload sizes are both 7, but only their size byte remains in the section.
  assert.deepEqual(parseReadyToRunDebug(Uint8Array.of(8, 1, 0, 0, 0x77),
    16, undefined, warnings), [{ runtimeFunctionIndex: 0, bounds: [], variables: [] }]);
  assert.match([...warnings].join(), /lookback/);
  assert.match([...warnings].join(), /index/);
  assert.match([...warnings].join(), /truncated/);
  assert.ok(warnings.has("DebugInfo payload is truncated."));
});

void test("resolves shared backward payloads without interpreting data as a new header", () => {
  // Entry at 4 looks back four bytes to a zero-sized payload header at section offset 0.
  const warnings = new Set<string>();

  assert.deepEqual(parseReadyToRunDebug(Uint8Array.of(8, 2, 0, 0, 4), 16,
    undefined, warnings), [{ runtimeFunctionIndex: 0, bounds: [], variables: [] }]);
  assert.deepEqual([...warnings], []);
});

void test("reuses decoded payload arrays for distinct runtime functions", () => {
  const warnings = new Set<string>();
  // Two-entry NativeArray; both leaf values encode a two-byte lookback to the same empty payload.
  // Node/index offsets follow the NativeArray tree layout documented in NativeArray.cs.
  const methods = parseReadyToRunDebug(Uint8Array.of(16, 1, 2, 2, 2, 30, 0, 0, 2),
    16, undefined, warnings);

  assert.equal(methods.length, 2);
  assert.equal(methods[0]?.bounds, methods[1]?.bounds);
  assert.equal(methods[0]?.variables, methods[1]?.variables);
  assert.deepEqual([...warnings], []);
});

void test("allows a shared payload at section offset zero", () => {
  const warnings = new Set<string>();

  // Leaf entry offset 3 points six bytes backward to the section's first empty payload header.
  assert.deepEqual(parseReadyToRunDebug(Uint8Array.of(8, 1, 0, 6), 16,
    undefined, warnings), [{ runtimeFunctionIndex: 0, bounds: [], variables: [] }]);
  assert.deepEqual([...warnings], []);
});
