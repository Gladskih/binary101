import assert from "node:assert/strict";
import { after, test } from "node:test";
import * as iced from "iced-x86-disasm";
import { Amd64PrologChecker } from "../../../../../../analyzers/pe/exception/amd64/prolog-check.js";
import type { Amd64PrologDescription } from "../../../../../../analyzers/pe/exception/amd64/prolog-types.js";
import { prologDescription as description } from "../../../../../helpers/pe-prolog-fixture.js";

const checker = new Amd64PrologChecker(iced);
after(() => checker.free());
const check = (bytes: number[], metadata: Amd64PrologDescription) =>
  checker.check(Uint8Array.from(bytes), metadata);

// Microsoft x64 UNWIND_CODE offsets point to the next instruction; RBX is register 3.
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-unwind_code
void test("matches a push and fixed allocation at their instruction ends", () => {
  assert.deepEqual(check([0x53, 0x48, 0x83, 0xec, 0x28], description([
    { opcode: "ALLOC_SMALL", codeOffset: 5, size: 40 },
    { opcode: "PUSH_NONVOL", codeOffset: 1, register: 3 }
  ], 5)), { issues: [], limitations: [] });
});

void test("reports the actual allocation instead of accepting the recorded size", () => {
  const result = check([0x48, 0x83, 0xec, 0x38, 0x90], description([
    { opcode: "ALLOC_SMALL", codeOffset: 4, size: 40 }
  ], 4));
  assert.equal(result.issues[0]?.code, "operation-mismatch");
  assert.match(result.issues[0]!.actual!, /sub rsp,38h/);
});

void test("reports a different pushed register", () => {
  assert.equal(check([0x57, 0x90], description([
    { opcode: "PUSH_NONVOL", codeOffset: 1, register: 3 }
  ], 1)).issues[0]?.code, "operation-mismatch");
});

void test("accepts push rax as an eight byte allocation", () => {
  assert.deepEqual(check([0x50], description([
    { opcode: "ALLOC_SMALL", codeOffset: 1, size: 8 }
  ], 1)), { issues: [], limitations: [] });
});

void test("detects a stack change omitted from unwind codes", () => {
  assert.equal(check([0x50, 0x90], description([], 1)).issues[0]?.code, "undescribed-stack");
});

void test("detects a CodeOffset in the middle of a decoded instruction", () => {
  assert.equal(check([0x48, 0x83, 0xec, 0x28], description([
    { opcode: "ALLOC_SMALL", codeOffset: 2, size: 40 }
  ], 4)).issues.some(issue => issue.code === "operation-boundary"), true);
});

void test("distinguishes a cut prolog boundary from missing file bytes", () => {
  assert.equal(check([0x48, 0x83, 0xec, 0x28], description([], 2))
    .limitations[0], "prolog-boundary");
  assert.deepEqual(check([0x48, 0x83], description([], 4)).limitations, ["unreadable-code"]);
});

void test("normalizes a home-area save made before stack allocation", () => {
  assert.deepEqual(check([0x48, 0x89, 0x5c, 0x24, 8, 0x48, 0x83, 0xec, 0x28], description([
    { opcode: "ALLOC_SMALL", codeOffset: 9, size: 40 },
    { opcode: "SAVE_NONVOL", codeOffset: 9, register: 3, displacement: 48 }
  ], 9)), { issues: [], limitations: [] });
});

void test("does not demand an instruction for a hardware machine frame", () => {
  assert.deepEqual(check([0x90], description([
    { opcode: "PUSH_MACHFRAME", codeOffset: 0, size: 40 }
  ], 1)), { issues: [], limitations: ["machine-frame"] });
});

void test("does not report mismatches for unsupported versions or chained records", () => {
  assert.deepEqual(check([0x90], description([], 1, { version: 3 })).limitations,
    ["unwind-version"]);
  assert.deepEqual(check([0x90], description([], 1, { flags: 4 })).limitations,
    ["chained-unwind"]);
});

void test("does not assume that a prolog uses the Windows ABI for unmentioned registers", () => {
  // Go's stack check commonly uses R12 as scratch before the frame setup.
  assert.deepEqual(check([0x4c, 0x8d, 0x64, 0x24, 0x88], description([], 5)),
    { issues: [], limitations: [] });
});

void test("checks partial-prolog unwind, not only the final frame", () => {
  // SAVE is wrongly activated before its final-RSP-relative displacement is valid.
  const result = check([0x48, 0x89, 0x5c, 0x24, 8, 0x48, 0x83, 0xec, 0x28], description([
    { opcode: "ALLOC_SMALL", codeOffset: 9, size: 40 },
    { opcode: "SAVE_NONVOL", codeOffset: 5, register: 3, displacement: 48 }
  ], 9));
  assert.equal(result.issues[0]?.offset, 5);
  assert.equal(result.issues[0]?.expected, "recover RBX");
});

void test("recognizes a frame pointer established before the final allocation", () => {
  assert.deepEqual(check([0x55, 0x48, 0x8b, 0xec, 0x48, 0x83, 0xec, 0x20], description([
    { opcode: "ALLOC_SMALL", codeOffset: 8, size: 32 },
    { opcode: "SET_FPREG", codeOffset: 4 },
    { opcode: "PUSH_NONVOL", codeOffset: 1, register: 5 }
  ], 8, { frameRegister: 5 })), { issues: [], limitations: [] });
});

void test("tracks a 32-bit immediate through RAX into an allocation", () => {
  assert.deepEqual(check([0xb8, 0x38, 0x12, 0, 0, 0x48, 0x29, 0xc4], description([
    { opcode: "ALLOC_LARGE", codeOffset: 8, size: 0x1238 }
  ], 8)), { issues: [], limitations: [] });
});

void test("keeps an unidentified stack-probe call incomplete without inventing a mismatch", () => {
  const result = check([0xb8, 0x38, 0x12, 0, 0, 0xe8, 0, 0, 0, 0, 0x48, 0x29, 0xc4], description([
    { opcode: "ALLOC_LARGE", codeOffset: 13, size: 0x1238 }
  ], 13));
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.limitations, ["unknown-stack-effect"]);
});

void test("stops at a branch and reports limited coverage", () => {
  assert.deepEqual(check([0x75, 0], description([], 2)),
    { issues: [], limitations: ["control-flow"] });
});

void test("does not interpret an early-return epilog as more prolog allocation", () => {
  assert.deepEqual(check([0x48, 0x83, 0xc4, 8], description([], 4)),
    { issues: [], limitations: ["stack-restoration"] });
});

void test("reports undecodable bytes separately", () => {
  assert.deepEqual(check([0x06], description([], 1)),
    { issues: [], limitations: ["undecodable-instruction"] });
});

void test("does not interpret an inherited entry context as a fresh function call", () => {
  assert.deepEqual(check([], description([
    { opcode: "ALLOC_SMALL", codeOffset: 0, size: 8 }
  ], 0)).limitations, ["entry-unwind-state"]);
});

for (const fields of [{ complete: false }, { flags: 8 }, { prologSize: -1 }, { prologSize: 256 }]) {
  void test(`rejects invalid metadata ${JSON.stringify(fields)} without decoding`, () => {
    assert.deepEqual(check([], description([], 0, fields)).limitations, ["invalid-unwind"]);
  });
}

for (const begin of [-1, 0x100000000, NaN, 1.5]) {
  void test(`reports invalid starting RVA ${begin}`, () => {
    assert.deepEqual(checker.check(new Uint8Array(), description([], 0), begin),
      { issues: [], limitations: ["invalid-function-range"] });
  });
}

void test("accepts zero and maximum encoded prolog sizes", () => {
  assert.deepEqual(check([], description([], 0)), { issues: [], limitations: [] });
  // SizeOfProlog is an unsigned byte in x64 v1/v2.
  assert.deepEqual(check(Array<number>(255).fill(0x90), description([], 255)),
    { issues: [], limitations: [] });
  assert.deepEqual(checker.check(new Uint8Array(), description([], 0), 0xffffffff),
    { issues: [], limitations: [] });
});

void test("keeps diagnostics relative to the function", () => {
  const result = checker.check(Uint8Array.from([0x48, 0x83, 0xec, 0x28, 0x90]), description([
    { opcode: "ALLOC_SMALL", codeOffset: 4, size: 56 }
  ], 4), 0x1000);
  assert.equal(result.issues[0]?.offset, 4);
});

void test("reports each distinct recovery assertion once at its earliest failure", () => {
  const result = check([0x57, 0x90, 0x90], description([
    { opcode: "PUSH_NONVOL", codeOffset: 1, register: 3 },
    { opcode: "ALLOC_SMALL", codeOffset: 2, size: 8 }
  ], 2));
  assert.deepEqual(result.issues.map(issue => [issue.expected, issue.offset]),
    [["recover RBX", 1], ["recover entry RSP", 2]]);
});

void test("checks frame displacements from an established nonzero frame offset", () => {
  // push rbp; sub rsp,64; lea rbp,[rsp+32].
  assert.deepEqual(check([0x55, 0x48, 0x83, 0xec, 0x40, 0x48, 0x8d, 0x6c, 0x24, 0x20], description([
    { opcode: "SET_FPREG", codeOffset: 10 },
    { opcode: "ALLOC_SMALL", codeOffset: 5, size: 64 },
    { opcode: "PUSH_NONVOL", codeOffset: 1, register: 5 }
  ], 10, { frameRegister: 5, frameOffset: 32 })), { issues: [], limitations: [] });
});

void test("does not claim a match when the frame header and operations disagree", () => {
  assert.deepEqual(check([], description([], 0, { frameRegister: 5 })).limitations, ["invalid-unwind"]);
  assert.deepEqual(check([], description([{ opcode: "SET_FPREG", codeOffset: 1 }], 1))
    .limitations, ["invalid-unwind"]);
});

void test("does not report a metadata-replay mismatch when Windows can unwind an early ret", () => {
  assert.deepEqual(check([0x90, 0xc3, 0x90, 0x90], description([
    { opcode: "ALLOC_SMALL", codeOffset: 1, size: 8 }
  ], 4)), { issues: [], limitations: ["epilog-in-prolog"] });
});

void test("does not apply fresh-call metadata to an already-restored tail transfer", () => {
  const result = checker.check(Uint8Array.from([0xb8, 1, 0, 0, 0, 0xe9, 0x20, 0, 0, 0]),
    description([{ opcode: "ALLOC_SMALL", codeOffset: 5, size: 32 }], 5), 0x1000, 0x100a);
  assert.deepEqual(result, { issues: [], limitations: ["epilog-in-prolog"] });
});

void test("does not validate a state outside the half-open pdata range", () => {
  assert.deepEqual(checker.check(Uint8Array.from([0x50]), description([], 1), 0x1000, 0x1001),
    { issues: [], limitations: ["function-end"] });
});

void test("releases native decoder, instruction and factory resources", context => {
  const local = new Amd64PrologChecker(iced);
  const decoder = context.mock.method(iced.Decoder.prototype, "free");
  const instruction = context.mock.method(iced.Instruction.prototype, "free");
  const factory = context.mock.method(local.factory, "free");
  local.check(Uint8Array.from([0x90]), description([], 1));
  local.free();
  assert.equal(decoder.mock.callCount(), 1);
  assert.equal(instruction.mock.callCount(), 1);
  assert.equal(factory.mock.callCount(), 1);
});

void test("keeps register restores that directly assign RSP outside the ordinary model", () => {
  assert.deepEqual(check([0x54, 0x90], description([
    { opcode: "PUSH_NONVOL", codeOffset: 1, register: 4 }
  ], 1)), { issues: [], limitations: ["stack-register-save"] });
});

void test("accepts ordinary prolog operations in a version two description", () => {
  assert.deepEqual(check([0x53, 0x90], { ...description([
    { opcode: "PUSH_NONVOL", codeOffset: 1, register: 3 }
  ], 1), version: 2 }), { issues: [], limitations: [] });
});

void test("continues through an indirect call before a described allocation", () => {
  // call rax; sub rsp,40. Unknown helper values stay volatile.
  assert.deepEqual(check([0xff, 0xd0, 0x48, 0x83, 0xec, 0x28], description([
    { opcode: "ALLOC_SMALL", codeOffset: 6, size: 40 }
  ], 6)), { issues: [], limitations: [] });
});

void test("deduplicates a repeated register assertion across later boundaries", () => {
  const result = check([0x57, 0x90, 0x90, 0x90], description([
    { opcode: "PUSH_NONVOL", codeOffset: 1, register: 3 }
  ], 3));
  assert.deepEqual(result.issues.map(issue => [issue.expected, issue.offset]), [["recover RBX", 1]]);
});

void test("reports an opaque early epilog state as incomplete", () => {
  assert.deepEqual(check([0x50, 0xc3, 0x90], description([], 1)),
    { issues: [], limitations: ["epilog-state-unknown"] });
});

void test("resolves an early relative tail transfer at its actual instruction RVA", () => {
  assert.deepEqual(checker.check(Uint8Array.from([0x90, 0xeb, 0x00]), description([
    { opcode: "ALLOC_SMALL", codeOffset: 1, size: 8 }
  ], 1), 0x1000, 0x1003), { issues: [], limitations: ["epilog-in-prolog"] });
});

void test("keeps new APX encodings outside the installed decoder's coverage", () => {
  // LLVM 22 recognizes this REX2-prefixed SCASQ. iced currently rejects REX2.
  assert.deepEqual(check([0xd5, 0x1e, 0xaf, 0x90], description([], 3)),
    { issues: [], limitations: ["undecodable-instruction"] });
});

void test("does not infer code boundaries from zero-sized prologs with later operations", () => {
  assert.deepEqual(check([0xc3], description([
    { opcode: "PUSH_NONVOL", codeOffset: 1, register: 5 }
  ], 0)), { issues: [], limitations: ["unwind-operation-range"] });
});
