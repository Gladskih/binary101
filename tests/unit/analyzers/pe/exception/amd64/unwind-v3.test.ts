import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeAmd64UnwindV3 } from "../../../../../../analyzers/pe/exception/amd64/unwind-v3.js";
import { createV3Unwind } from "../../../../../fixtures/pe-unwind-v3.js";

// Header, epilog inheritance, instruction offsets, and pool references:
// https://learn.microsoft.com/en-us/cpp/build/x64-unwind-information-v3
void test("V3 decodes shared prolog and epilog WODs without reading trailing padding", () => {
  const issues: string[] = [];
  const record = decodeAmd64UnwindV3(createV3Unwind(
    [0, 8, 0xfb, 0xff, 0, 0, 4, 0, 0x48], 1 | (1 << 5), 0, 4), issues);

  assert.deepEqual(record, { flags: 0, prologSize: 4, prologIpOffsets: [0],
    prologOperations: [{ opcode: "ALLOC_SMALL", size: 40 }], epilogs: [
      { kind: "full", flags: 0, offset: -5, firstOp: 0, lastInstructionOffset: 4,
        ipOffsets: [0], operations: [{ opcode: "ALLOC_SMALL", size: 40 }] }
    ] });
  const epilog = record?.epilogs[0];
  assert.ok(epilog?.kind === "full");
  assert.equal(record?.prologOperations[0], epilog.operations[0]);
  assert.deepEqual(issues, []);
});

void test("V3 LARGE extends prolog size and widens prolog and epilog offsets independently", () => {
  const issues: string[] = [];
  const record = decodeAmd64UnwindV3(createV3Unwind(
    [1, 5, 1, 10, 0xf7, 0xfe, 0, 0, 9, 1, 5, 1, 0x18], 1 | (1 << 5), 8, 9), issues);

  assert.equal(record?.prologSize, 265);
  assert.deepEqual(record?.prologIpOffsets, [261]);
  assert.deepEqual(record?.epilogs, [{ kind: "full", flags: 2, offset: -265,
    firstOp: 0, lastInstructionOffset: 265, ipOffsets: [261],
    operations: [{ opcode: "ALLOC_SMALL", size: 16 }] }]);
  assert.deepEqual(issues, []);
});

void test("V3 inherited epilogs retain the most recent full descriptor as their source", () => {
  const issues: string[] = [];
  const record = decodeAmd64UnwindV3(createV3Unwind([
    8, 10, 0, 0, 0, 1, 0,
    8, 10, 0, 1, 0, 1, 0,
    0, 10, 0, 0x1c, 0x3c
  ], 3 << 5), issues);

  assert.deepEqual(record?.epilogs[2], { kind: "inherited", flags: 0, offset: 30, baseEpilogIndex: 1 });
  assert.deepEqual(record?.epilogs[1], { kind: "full", flags: 0, offset: 20, firstOp: 1,
    lastInstructionOffset: 1, ipOffsets: [0], operations: [{ opcode: "PUSH", register: 7 }] });
  assert.deepEqual(issues, []);
});

void test("V3 accepts empty payloads and respects nonzero DataView offsets", () => {
  const bytes = Uint8Array.of(255, 3, 0, 0, 0, 255);
  const issues: string[] = [];

  assert.deepEqual(decodeAmd64UnwindV3(new DataView(bytes.buffer, 1, 4), issues), {
    flags: 0, prologSize: 0, prologIpOffsets: [], prologOperations: [], epilogs: []
  });
  assert.deepEqual(issues, []);
});

for (const bytes of [[], [3], [3, 0, 0], [1, 0, 0, 0]]) {
  void test(`V3 rejects an incomplete or wrong-version header ${bytes}`, () => {
    const issues: string[] = [];

    assert.equal(decodeAmd64UnwindV3(new DataView(Uint8Array.from(bytes).buffer), issues), null);
    assert.deepEqual(issues, ["UNWIND_INFO v3 header is truncated or has an invalid version."]);
  });
}

for (const [bytes, expected] of [
  [[3, 0, 1, 0], "payload is shorter"],
  [[0x43, 0, 0, 0], "large prolog extension"],
  [[3, 0, 0, 1], "instruction offset"],
  [[3, 0, 0, 32], "epilog flags"],
  [[3, 0, 1, 32, 8, 0], "epilog offset"],
  [[3, 0, 2, 32, 8, 0, 0, 0], "epilog FirstOp"],
  [[3, 0, 3, 32, 10, 0, 0, 0, 0, 0], "epilog last instruction"],
  [[3, 0, 3, 32, 8, 0, 0, 0, 0, 1], "instruction offset"],
  // Extra bytes after PayloadWords must not satisfy a missing payload field.
  [[3, 4, 1, 33, 0, 8, 0, 0, 0, 0, 4, 0, 0x48], "epilog offset"]
] as const) {
  void test(`V3 reports truncation while reading ${expected}`, () => {
    const issues: string[] = [];

    assert.equal(decodeAmd64UnwindV3(new DataView(Uint8Array.from(bytes).buffer), issues), null);
    assert.ok(issues.some(issue => issue.includes(expected)));
  });
}

for (const [payload, control, flags, prologSize, expected] of [
  [[], 0, 16, 0, "reserved header flag"],
  [[4, 0, 0], 32, 0, 0, "reserved flag"],
  [[0, 0, 0], 32, 0, 0, "without a preceding"],
  [[8, 0, 0, 0, 0, 1, 0, 1, 1, 0, 4], 64, 0, 0, "flags disagree"],
  [[8, 10, 0, 0, 0, 1, 0, 0, 0xff, 0xff, 4], 64, 0, 0, "consistent direction"],
  [[4, 4], 1, 0, 4, "prolog instruction offsets"],
  [[0, 1, 4, 4], 2, 0, 4, "prolog instruction offsets"],
  [[16, 0, 0, 0, 0, 1, 1, 0, 4, 4], 32, 0, 0, "epilog instruction offsets"],
  [[8, 0, 0, 0, 0, 1, 2, 4], 32, 0, 0, "epilog instruction offsets"],
  [[0, 0x10], 1, 0, 4, "invalid or truncated WOD"]
] as const) {
  void test(`V3 retains bounded metadata and warns about ${expected}`, () => {
    const issues: string[] = [];
    const record = decodeAmd64UnwindV3(createV3Unwind(payload, control, flags, prologSize), issues);

    assert.ok(record);
    assert.ok(issues.some(issue => issue.includes(expected)));
  });
}

void test("V3 detects mixed epilog directions after a zero initial displacement", () => {
  const issues: string[] = [];
  const record = decodeAmd64UnwindV3(createV3Unwind([
    8, 0, 0, 0, 0, 1, 0, 0, 10, 0, 0, 0xf6, 0xff, 4
  ], 3 << 5), issues);

  assert.ok(record);
  assert.deepEqual(issues, ["UNWIND_INFO v3 epilog displacements do not have a consistent direction."]);
});

for (const [payload, control, prologSize] of [
  [[0, 0, 4, 4], 2, 1],
  [[16, 0, 0, 0, 0, 0, 0, 0, 4, 4], 32, 0],
  [[16, 0, 0, 0, 0, 1, 0, 1, 4, 4], 32, 0],
  [[8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 4], 64, 0]
] as const) {
  void test(`V3 accepts ordered or equal instruction offsets and zero epilog deltas: ${payload}`, () => {
    const issues: string[] = [];
    const record = decodeAmd64UnwindV3(createV3Unwind(payload, control, 0, prologSize), issues);

    assert.ok(record);
    assert.deepEqual(issues, []);
  });
}
