import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeArm64UnwindPool } from "../../../../../analyzers/pe/exception/arm64-unwind-code-pool.js";

const pool = (bytes: number[], starts: number[], issues: string[]) =>
  decodeArm64UnwindPool(new DataView(Uint8Array.from(bytes).buffer), new Set(starts), issues);

void test("ARM64 shared tails are inventoried once and alignment padding is excluded", () => {
  const issues: string[] = [];
  const result = pool([0xe3, 2, 0xc8, 1, 0xe4, 255, 255, 255], [1, 0, 4], issues);

  assert.deepEqual(result.operations.map(value => [value.offset, value.opcode]),
    [[0, "nop"], [1, "alloc_s"], [2, "save_regp"], [4, "end"]]);
  assert.equal(result.hasDecodeGaps, false);
  assert.deepEqual(issues, []);
});

// Windows unwinder accumulates SAVE_NEXT prefixes before restoring the base pair.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/unwinder/arm64/unwinder.cpp
void test("ARM64 SAVE_NEXT resolves increasing register pairs in reverse prolog order", () => {
  const issues: string[] = [];
  const result = pool([0xe6, 0xe6, 0xc8, 1, 0xe4], [0, 1, 2], issues);

  assert.deepEqual(result.operations.filter(value => value.kind === "save").map(value =>
    [value.opcode, value.registers, value.displacement, value.addressing]), [
    ["save_next", ["X23", "X24"], 40, "offset"],
    ["save_next", ["X21", "X22"], 24, "offset"],
    ["save_regp", ["X19", "X20"], 8, "offset"]
  ]);
  assert.deepEqual(issues, []);
});

void test("ARM64 SAVE_NEXT uses save-area offsets independently of pre-index stack adjustment", () => {
  const issues: string[] = [];
  const result = pool([0xe6, 0xcc, 3, 0xe4], [0], issues);

  assert.deepEqual(result.operations.filter(value => value.kind === "save").map(value =>
    [value.registers, value.displacement, value.addressing]), [
    [["X21", "X22"], 16, "offset"], [["X19", "X20"], -32, "preIndex"]
  ]);
  assert.deepEqual(issues, []);
});

for (const [bytes, expected] of [
  [[0xe6, 0xd8, 0, 0xe4], ["D10", "D11"]],
  [[0xe6, 0xe7, 0x40, 0x80, 0xe4], ["Q2", "Q3"]],
  [[0xe6, 0xca, 0, 0xe4], ["X29", "LR"]]
] as const) {
  void test(`ARM64 SAVE_NEXT respects register classes ${expected.join(",")}`, () => {
    const issues: string[] = [];
    const result = pool([...bytes], [0], issues);
    const operation = result.operations[0];

    assert.ok(operation?.kind === "save");
    assert.deepEqual(operation.registers, expected);
    assert.equal(operation.displacement, expected[0] === "Q2" ? 32 : 16);
    assert.deepEqual(issues, []);
  });
}

void test("ARM64 END_C preserves the phantom parent prolog up to its real END", () => {
  const issues: string[] = [];
  const result = pool([0xe5, 3, 0xe4, 255], [0, 1], issues);

  assert.deepEqual(result.operations.map(value => value.opcode), ["end_c", "alloc_s", "end"]);
  assert.deepEqual(issues, []);
});

for (const [bytes, expected] of [
  [[0xe6, 0xe4], /no compatible following pair/],
  [[0xe6, 0x40, 0xe4], /no compatible following pair/],
  [[0xe6, 0xe7, 0, 0, 0xe4], /no compatible following pair/],
  [[0xe6, 0xe7, 0x5e, 0x40, 0xe4], /exceeds its register bank/],
  [[0xe6, 0xca, 0x80, 0xe4], /exceeds its register bank/],
  [[0xe6], /out of bounds/],
  [[0xe6, 0xff], /unknown or reserved/],
  [[0xe3], /no end opcode/],
  [[0xe5], /no end opcode/]
] as const) {
  void test(`ARM64 pool diagnoses invalid sequence ${bytes.join(",")}`, () => {
    const issues: string[] = [];
    const result = pool([...bytes], [0], issues);

    assert.equal(result.hasDecodeGaps, true);
    assert.match(issues.join(" "), expected);
  });
}

void test("ARM64 epilog indices cannot start in another operation's operands", () => {
  const issues: string[] = [];
  const result = pool([0xe0, 0, 0, 1, 0xe4], [3, 0, 1], issues);

  assert.equal(result.operations.length, 2);
  assert.equal(result.hasDecodeGaps, true);
  assert.match(issues.join(" "), /inside an operand at byte 1/);
  assert.match(issues.join(" "), /inside an operand at byte 3/);
});

void test("ARM64 rejected opcode suffixes are not repeatedly decoded across shared references", () => {
  const issues: string[] = [];
  const result = pool([0xe6, 0xff], [0, 1], issues);

  assert.equal(result.hasDecodeGaps, true);
  assert.equal(issues.filter(value => value.includes("unknown or reserved")).length, 1);
});

for (const start of [-1, 0.5, Infinity, NaN, 1]) {
  void test(`ARM64 rejects pool index ${start}`, () => {
    const issues: string[] = [];
    const result = pool([0xe4], [start], issues);

    assert.deepEqual(result.operations, []);
    assert.equal(result.hasDecodeGaps, true);
    assert.match(issues[0]!, /outside its code pool/);
  });
}

void test("ARM64 empty code pools do not pretend to contain a valid prolog", () => {
  const issues: string[] = [];
  const result = pool([], [0], issues);
  assert.equal(result.hasDecodeGaps, true);
  assert.match(issues[0]!, /outside its code pool/);
});

void test("ARM64 long unfinished SAVE_NEXT chains retain one bounded diagnostic and their stored prefixes", () => {
  const issues: string[] = [];
  // Maximum code pool: Extended Code Words is an eight-bit count of DWORDs.
  const result = pool(new Array<number>(255 * 4).fill(0xe6), [0], issues);

  assert.equal(result.operations.length, 1020);
  assert.equal(result.hasDecodeGaps, true);
  assert.deepEqual(issues, ["ARM64 unwind operation offset is out of bounds.",
    "ARM64 unwind sequence at byte 0 has no end opcode."]);
});

for (const [bytes, names] of [[[0xe6, 0x22, 0xe4], ["X21", "X22"]],
  [[0xe6, 0xda, 1, 0xe4], ["D10", "D11"]], [[0xe6, 0xe7, 0x5c, 0x40, 0xe4], ["D30", "D31"]],
  [[0xe6, 0xe7, 0x5e, 0x40, 0xe4], null]] as const) {
  void test(`ARM64 SAVE_NEXT validates pair boundary ${bytes.join(",")}`, () => {
    const issues: string[] = [];
    const result = pool([...bytes], [0], issues);
    const operation = result.operations[0];

    assert.equal(operation?.kind, names ? "save" : "marker");
    assert.deepEqual(operation?.kind === "save" ? operation.registers : null, names);
    assert.equal(result.hasDecodeGaps, names == null);
  });
}
