import assert from "node:assert/strict";
import test from "node:test";
import { readX86ReadyToRunThunk } from
  "../../../../../analyzers/pe/clr/ready-to-run-thunk-x86.js";

const code = (hex: string): DataView => new DataView(Uint8Array.from(Buffer.from(hex, "hex")).buffer);

// Target_X64/Target_X86-ImportThunk.cs, dotnet/runtime v10.0.0 emit these sequences.
// FF25/FF35 operands on x86 are absolute VAs; x64 uses RIP-relative displacements.
void test("decodes all x64 prefixes and RIP-relative helper/module cells", () => {
  assert.deepEqual(readX86ReadyToRunThunk(code("ff2500000000"), 0x1000, 0x8664, 0n),
    { rva: 0x1000, size: 6, kind: "eager", helperCellRva: 0x1006 });
  assert.deepEqual(readX86ReadyToRunThunk(code("33c06a03ff3500000000ff2500000000"), 0x1000, 0x8664, 0n),
    { rva: 0x1000, size: 16, kind: "delay-load", helperCellRva: 0x1010,
      moduleCellRva: 0x100a, importSectionIndex: 3 });
  assert.equal(readX86ReadyToRunThunk(code("6a04ff3500000000ff2500000000"), 0x1000, 0x8664, 0n)?.kind,
    "tailcall");
  assert.equal(readX86ReadyToRunThunk(code("498bc36a01ff3500000000ff2500000000"), 0x1000, 0x8664, 0n)?.kind,
    "virtual-dispatch");
  assert.deepEqual(readX86ReadyToRunThunk(code("488b1500000000ff2500000000"), 0x1000, 0x8664, 0n),
    { rva: 0x1000, size: 13, kind: "lazy", helperCellRva: 0x100d, moduleCellRva: 0x1007 });
  assert.equal(readX86ReadyToRunThunk(code("488b3500000000ff2500000000"), 0x1000, 0x8664, 0n)?.kind, "lazy");
});

void test("decodes x86 absolute pointers and signed PUSH imm8 indices", () => {
  assert.deepEqual(readX86ReadyToRunThunk(code("ff2500304000"), 0x1000, 0x14c, 0x400000n),
    { rva: 0x1000, size: 6, kind: "eager", helperCellRva: 0x3000 });
  assert.deepEqual(readX86ReadyToRunThunk(code("8b1500204000ff2500304000"), 0x1000, 0x14c, 0x400000n),
    { rva: 0x1000, size: 12, kind: "lazy", helperCellRva: 0x3000, moduleCellRva: 0x2000 });
  assert.deepEqual(readX86ReadyToRunThunk(code("33c06affff3500204000ff2500304000"), 0x1000, 0x14c, 0x400000n),
    { rva: 0x1000, size: 16, kind: "delay-load", helperCellRva: 0x3000,
      moduleCellRva: 0x2000, importSectionIndex: -1 });
  assert.equal(readX86ReadyToRunThunk(code("6a04ff3500204000ff2500304000"), 0x1000, 0x14c, 0x400000n), null);
});

void test("rejects truncation, unknown opcodes and altered transfers", () => {
  assert.equal(readX86ReadyToRunThunk(code(""), 0x1000, 0x8664, 0n), null);
  assert.equal(readX86ReadyToRunThunk(code("ff2500"), 0x1000, 0x8664, 0n), null);
  assert.equal(readX86ReadyToRunThunk(code("488b1500000000ff2400000000"), 0x1000, 0x8664, 0n), null);
  assert.equal(readX86ReadyToRunThunk(code("33c06a03ff3400000000ff2500000000"), 0x1000, 0x8664, 0n), null);
  assert.equal(readX86ReadyToRunThunk(code("909090909090"), 0x1000, 0x8664, 0n), null);
  assert.equal(readX86ReadyToRunThunk(code("ff2500000000"), 0x1000, 0xaa64, 0n), null);
});

void test("retains known code while marking impossible data addresses unresolved", () => {
  assert.equal(readX86ReadyToRunThunk(code("ff2500000000"), 0, 0x14c, 0n)?.helperCellRva, 0);
  assert.equal(readX86ReadyToRunThunk(code("ff2500000000"), 0, 0x14c, -0x100000000n)?.helperCellRva, null);
  assert.equal(readX86ReadyToRunThunk(code("ff25ffffffff"), 0, 0x14c, 0x100000000n)?.helperCellRva, null);
  assert.equal(readX86ReadyToRunThunk(code("ff2500000080"), 0, 0x8664, 0n)?.helperCellRva, null);
  assert.equal(readX86ReadyToRunThunk(code("ff25ff7f0000"), 0xfffffff0, 0x8664, 0n)?.helperCellRva, null);
});

void test("rejects mismatched prefixes even when helper and module transfers are valid", () => {
  assert.equal(readX86ReadyToRunThunk(code("90c06a03ff3500000000ff2500000000"),
    0x1000, 0x8664, 0n), null);
  assert.equal(readX86ReadyToRunThunk(code("9004ff3500000000ff2500000000"),
    0x1000, 0x8664, 0n), null);
  assert.equal(readX86ReadyToRunThunk(code("498bc26a01ff3500000000ff2500000000"),
    0x1000, 0x8664, 0n), null);
  assert.equal(readX86ReadyToRunThunk(code("488b1400000000ff2500000000"),
    0x1000, 0x8664, 0n), null);
  assert.equal(readX86ReadyToRunThunk(code("488b3400000000ff2500000000"),
    0x1000, 0x8664, 0n), null);
  assert.equal(readX86ReadyToRunThunk(code("8b1400000000ff2500000000"),
    0x1000, 0x14c, 0n), null);
});
