import assert from "node:assert/strict";
import { test } from "node:test";
import { readDebugBounds } from "../../../../../analyzers/pe/clr/ready-to-run-debug-bounds.js";
import { nibbleIntegers, packedDebugBounds } from "../../../../helpers/ready-to-run-debug-fixture.js";

void test("decodes .NET 9 nibble bounds and IL prolog, epilog and unmapped sentinels", () => {
  const bytes = nibbleIntegers([4, 0, 1, 1, 2, 2, 8, 3, 3, 2, 0, 7, 16]);
  const warnings = new Set<string>();

  assert.deepEqual(readDebugBounds(bytes, 10, warnings), [
    { nativeOffset: 0, ilOffset: -2, source: 1 },
    { nativeOffset: 2, ilOffset: -1, source: 8 },
    { nativeOffset: 5, ilOffset: 0, source: 2 },
    { nativeOffset: 5, ilOffset: 4, source: 16 }
  ]);
  assert.deepEqual([...warnings], []);
});

void test("decodes .NET 10 bit-packed bounds across byte and 32-bit boundaries", () => {
  const bytes = packedDebugBounds([3n | (3n << 2n) | (9n << 34n)], 32, 32);
  const warnings = new Set<string>();

  assert.deepEqual(readDebugBounds(bytes, 16, warnings), [
    { nativeOffset: 3, ilOffset: 6, source: 18 }
  ]);
  assert.deepEqual([...warnings], []);
});

void test("keeps complete bounds before truncation", () => {
  const warnings = new Set<string>();

  assert.deepEqual(readDebugBounds(nibbleIntegers([2, 1, 3, 2]), 10, warnings), [
    { nativeOffset: 1, ilOffset: 0, source: 2 }
  ]);
  assert.match([...warnings].join(), /truncated/);
});

void test("rejects bit widths beyond UInt32 and detects native offset overflow", () => {
  const warnings = new Set<string>();

  assert.deepEqual(readDebugBounds(nibbleIntegers([1, 32, 0]), 16, warnings), []);
  assert.deepEqual(readDebugBounds(nibbleIntegers([2, 0xffffffff, 0, 0, 1, 0, 0]),
    10, warnings), [{ nativeOffset: 0xffffffff, ilOffset: -3, source: 0 }]);
  assert.match([...warnings].join(), /bit width/);
  assert.match([...warnings].join(), /overflow/);
});

void test("checks both packed widths, partial bit fields and cumulative UInt32 overflow", () => {
  const warnings = new Set<string>();
  const overflow = packedDebugBounds([0xfffffffcn, 4n], 30, 1);

  assert.deepEqual(readDebugBounds(nibbleIntegers([1, 0, 32]), 16, warnings), []);
  assert.deepEqual(readDebugBounds(packedDebugBounds([0n], 1, 1).subarray(0, 2),
    16, warnings), []);
  assert.equal(readDebugBounds(overflow, 16, warnings).length, 2);
  assert.deepEqual(readDebugBounds(packedDebugBounds([0x3fffffffcn, 4n], 32, 1),
    16, warnings), [{ nativeOffset: 0xffffffff, ilOffset: -3, source: 0 }]);
  assert.match([...warnings].join(), /bit width/);
  assert.match([...warnings].join(), /truncated/);
  assert.match([...warnings].join(), /overflow/);
});

void test("advances through consecutive packed entries and accepts an exact byte ending", () => {
  const warnings = new Set<string>();

  assert.deepEqual(readDebugBounds(packedDebugBounds([329n, 526n, 0n], 4, 4), 16, warnings), [
    { nativeOffset: 2, ilOffset: 2, source: 16 },
    { nativeOffset: 5, ilOffset: 5, source: 2 },
    { nativeOffset: 5, ilOffset: -3, source: 0 }
  ]);
  assert.deepEqual(readDebugBounds(packedDebugBounds([0n], 4, 2), 16, warnings), [
    { nativeOffset: 0, ilOffset: -3, source: 0 }
  ]);
  assert.deepEqual([...warnings], []);
});
