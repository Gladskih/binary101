import assert from "node:assert/strict";
import { test } from "node:test";
import { addDecodedInstructionRange, mergeDecodedInstructionRanges, overlapsDecodedInstructions,
  type DecodedInstructionRange } from "../../../../../analyzers/pe/disassembly/code-string-instruction-ranges.js";

const addLinearCode = (ranges: DecodedInstructionRange[]): void => {
  // Memory regression: one linear block must not require an object per instruction.
  for (let offset = 0; offset < 10000; offset++) addDecodedInstructionRange(ranges, 0x1000 + offset, 1);
};

void test("a dense linear block retains one exact range", () => {
  const ranges: DecodedInstructionRange[] = [];

  addLinearCode(ranges);

  assert.deepEqual(ranges, [{ startRva: 0x1000, endRva: 0x1000 + 10000 }]);
});

void test("adjacent, reverse and overlapping runs preserve holes and every covered byte", () => {
  const ranges: DecodedInstructionRange[] = [];

  addDecodedInstructionRange(ranges, 20, 4);
  addDecodedInstructionRange(ranges, 18, 2);
  addDecodedInstructionRange(ranges, 22, 4);
  addDecodedInstructionRange(ranges, 40, 2);
  addDecodedInstructionRange(ranges, 10, 2);
  addDecodedInstructionRange(ranges, 11, 1);

  assert.deepEqual(ranges, [{ startRva: 18, endRva: 26 }, { startRva: 40, endRva: 42 },
    { startRva: 10, endRva: 12 }]);
  assert.deepEqual(mergeDecodedInstructionRanges(ranges), [
    { startRva: 10, endRva: 12 }, { startRva: 18, endRva: 26 }, { startRva: 40, endRva: 42 }]);
});

void test("final merging joins bridged runs without changing the recorded runs", () => {
  const ranges = [{ startRva: 20, endRva: 24 }, { startRva: 10, endRva: 15 },
    { startRva: 14, endRva: 21 }];

  assert.deepEqual(mergeDecodedInstructionRanges(ranges), [{ startRva: 10, endRva: 24 }]);
  assert.deepEqual(ranges, [{ startRva: 20, endRva: 24 }, { startRva: 10, endRva: 15 },
    { startRva: 14, endRva: 21 }]);
});

void test("final merging compacts adjacent and same-start runs", () => {
  assert.deepEqual(mergeDecodedInstructionRanges([
    { startRva: 10, endRva: 20 }, { startRva: 10, endRva: 15 }, { startRva: 0, endRva: 10 }
  ]), [{ startRva: 0, endRva: 20 }]);
});

void test("overlap lookup finds code in a single compacted run", () => {
  const ranges = [{ startRva: 10, endRva: 20 }];

  assert.equal(overlapsDecodedInstructions(ranges, 10, 1), true);
  assert.equal(overlapsDecodedInstructions(ranges, 19, 1), true);
  assert.equal(overlapsDecodedInstructions(ranges, 20, 1), false);
});

for (const [rva, length] of [[-1, 1], [0.5, 1], [NaN, 1], [Infinity, 1],
  [0, 0], [0, -1], [0, 0.5], [0, NaN], [0, Infinity], [0xffffffff, 2]]) {
  void test(`invalid instruction range ${rva}, ${length} is ignored`, () => {
    const ranges: DecodedInstructionRange[] = [];

    addDecodedInstructionRange(ranges, rva!, length!);

    assert.deepEqual(ranges, []);
  });
}

void test("the last RVA byte and empty range collection remain valid", () => {
  const ranges: DecodedInstructionRange[] = [];

  addDecodedInstructionRange(ranges, 0xffffffff, 1);

  assert.deepEqual(ranges, [{ startRva: 0xffffffff, endRva: 0x100000000 }]);
  assert.deepEqual(mergeDecodedInstructionRanges([]), []);
  assert.equal(overlapsDecodedInstructions([], 0, 1), false);
});

for (const [rva, length, expected] of [[9, 1, false], [9, 2, true], [10, 1, true],
  [15, 1, false], [25, 1, true], [30, 1, false], [35, 10, true], [44, 1, false],
  [-1, 1, true], [NaN, 1, true], [0, 0, true], [0, 0.5, true], [0, Infinity, true],
  [0xffffffff, 2, true]] as const) {
  void test(`string range ${rva}, ${length} has conservative overlap ${expected}`, () => {
    assert.equal(overlapsDecodedInstructions([
      { startRva: 10, endRva: 15 }, { startRva: 20, endRva: 30 }, { startRva: 40, endRva: 44 }
    ], rva, length), expected);
  });
}

const assertExactByteUnion = (): void => {
  const ranges: DecodedInstructionRange[] = [];
  const expected = new Uint8Array(256);
  for (let index = 0; index < 100; index++) {
    const start = (index * 37) % 240;
    const length = index % 15 + 1;
    addDecodedInstructionRange(ranges, start, length);
    expected.fill(1, start, start + length);
  }
  const merged = mergeDecodedInstructionRanges(ranges);
  assert.deepEqual(Array.from(expected, (_, address) => overlapsDecodedInstructions(merged, address, 1)),
    Array.from(expected, value => value === 1));
};

void test("reordered and overlapping runs retain exactly the independently marked bytes", () => {
  assertExactByteUnion();
});

void test("a missing internal range slot does not throw", () => {
  assert.equal(overlapsDecodedInstructions(new Array<DecodedInstructionRange>(1), 0, 1), false);
});
