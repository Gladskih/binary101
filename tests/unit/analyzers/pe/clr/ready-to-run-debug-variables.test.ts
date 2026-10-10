import assert from "node:assert/strict";
import { test } from "node:test";
import { readDebugVariables } from "../../../../../analyzers/pe/clr/ready-to-run-debug-variables.js";
import { debugVariables, nibbleIntegers } from "../../../../helpers/ready-to-run-debug-fixture.js";

// Independent test oracle: these are ordinal VarLocType values, not production parser constants.
// cordebuginfo.h lists VLT_REG through VLT_FIXED_VA in this exact enum order.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/cordebuginfo.h
const varLoc = {
  register: 0, registerByref: 1, fpRegister: 2, stack: 3, stackByref: 4,
  registerPair: 5, registerStack: 6, stackRegister: 7, stackPair: 8, fpStack: 9, varargs: 10,
  count: 11
} as const;

// AMD64 RegNum is zero-based in cordebuginfo.h (RAX, RCX, RDX, RBX, RSP, RBP, ...).
const amd64Register = { rax: 0, rcx: 1, rdx: 2, rbx: 3, rsp: 4, rbp: 5 } as const;
const i386Register = { eax: 0, ecx: 1, edx: 2, ebx: 3, esp: 4, ebp: 5 } as const;
// The PE/COFF machine IDs and CoreCLR Linux override used by this independent test oracle.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/pedecoder.h
const machine = { amd64: 0x8664, i386: 0x014c, linuxOverride: 0x7b79 } as const;

// NibbleReader uses signed low-bit encoding: odd n => -(n >> 1), even n => n / 2.
const signedNibble = (value: number): number => value < 0 ? -2 * value + 1 : 2 * value;

void test("decodes all eleven cordebuginfo variable location variants and implicit arguments", () => {
  const bytes = debugVariables([
    // cordebuginfo.h names UNKNOWN_ILNUM=-4, TYPECTXT_ILNUM=-3, RETBUF_ILNUM=-2, VARARGS_HND_ILNUM=-1.
    { start: 0, length: 2, variableNumber: -4, location: varLoc.register, operands: [amd64Register.rax] },
    { start: 0, length: 2, variableNumber: -3, location: varLoc.registerByref, operands: [amd64Register.rcx] },
    { start: 0, length: 2, variableNumber: -2, location: varLoc.fpRegister, operands: [3] }, // ST(3)
    // Stack operands are base RegNum then signed byte displacement; encoded -3 is nibble 7.
    { start: 0, length: 2, variableNumber: -1, location: varLoc.stack,
      operands: [amd64Register.rbp, signedNibble(-3)] },
    { start: 0, length: 2, variableNumber: 0, location: varLoc.stackByref,
      operands: [amd64Register.rsp, signedNibble(3)] },
    { start: 0, length: 2, variableNumber: 1, location: varLoc.registerPair,
      operands: [amd64Register.rax, amd64Register.rcx] },
    { start: 0, length: 2, variableNumber: 2, location: varLoc.registerStack,
      operands: [amd64Register.rax, amd64Register.rbp, signedNibble(-3)] },
    // VLT_STK_REG stores the stack pair first, the reverse of VLT_REG_STK.
    { start: 0, length: 2, variableNumber: 3, location: varLoc.stackRegister,
      operands: [signedNibble(-3), amd64Register.rbp, amd64Register.rax] },
    { start: 0, length: 2, variableNumber: 4, location: varLoc.stackPair,
      operands: [amd64Register.rbp, signedNibble(3)] },
    { start: 0, length: 2, variableNumber: 5, location: varLoc.fpStack, operands: [3] }, // ST(3)
    // VLT_FIXED_VA offset is relative to VARARGS_HANDLE per cordebuginfo.h.
    { start: 0, length: 2, variableNumber: 6, location: varLoc.varargs, operands: [8] }
  ]);
  const warnings = new Set<string>();

  assert.deepEqual(readDebugVariables(bytes, machine.amd64, warnings).map(entry => entry.location), [
    { kind: "register", register: amd64Register.rax }, { kind: "register-byref", register: amd64Register.rcx },
    { kind: "fp-register", register: 3 }, { kind: "stack", baseRegister: amd64Register.rbp, offset: -3 },
    { kind: "stack-byref", baseRegister: amd64Register.rsp, offset: 3 },
    { kind: "register-pair", register1: amd64Register.rax, register2: amd64Register.rcx },
    { kind: "register-stack", register: amd64Register.rax, baseRegister: amd64Register.rbp, offset: -3 },
    { kind: "stack-register", offset: -3, baseRegister: amd64Register.rbp, register: amd64Register.rax },
    { kind: "stack-pair", baseRegister: amd64Register.rbp, offset: 3 },
    { kind: "fp-stack", index: 3 }, { kind: "varargs", offset: 8 }
  ]);
  assert.equal(readDebugVariables(bytes, machine.amd64, warnings)[0]?.variableNumber, -4);
  assert.deepEqual([...warnings], []);
});

void test("scales x86 stack offsets and decodes OS-overridden target machine IDs", () => {
  const warnings = new Set<string>();

  // IMAGE_FILE_MACHINE_I386 XOR .NET's Linux override identifies the target; signed -3 slots
  // become -12 bytes because the x86 stack slot is sizeof(DWORD), 4 bytes.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/pedecoder.h
  assert.deepEqual(readDebugVariables(debugVariables([{ start: 4, length: 5, variableNumber: 0,
    location: varLoc.stack, operands: [i386Register.edx, signedNibble(-3)] }]),
    machine.i386 ^ machine.linuxOverride, warnings), [{ startOffset: 4, endOffset: 9, variableNumber: 0,
    location: { kind: "stack", baseRegister: i386Register.edx, offset: -12 } }]);
  assert.deepEqual([...warnings], []);
});

void test("keeps complete variable records before unknown locations and truncated operands", () => {
  const warnings = new Set<string>();

  // VLT_COUNT=11 is a sentinel, not a valid tag; it follows a complete VLT_REG record.
  assert.equal(readDebugVariables(nibbleIntegers([2, 0, 1, 4, varLoc.register, amd64Register.rax,
    0, 1, 4, varLoc.count]),
    undefined, warnings).length, 1);
  // VLT_REG_STK needs register, base register, and signed offset; the stream ends at the tag.
  assert.deepEqual(readDebugVariables(nibbleIntegers([1, 0, 1, 4, varLoc.registerStack]),
    undefined, warnings), []);
  assert.match([...warnings].join(), /location/);
  assert.match([...warnings].join(), /truncated/);
});

void test("rejects overflowing variable lifetimes", () => {
  const warnings = new Set<string>();

  assert.deepEqual(readDebugVariables(debugVariables([{ start: 0xffffffff, length: 1,
    variableNumber: 0, location: varLoc.register, operands: [amd64Register.rcx] }]),
    undefined, warnings), []);
  assert.match([...warnings].join(), /overflow/);
});

void test("reports an unknown target instead of guessing stack-offset scaling", () => {
  const warnings = new Set<string>();

  assert.deepEqual(readDebugVariables(debugVariables([{ start: 0, length: 1, variableNumber: 0,
    location: varLoc.stack, operands: [amd64Register.rdx, signedNibble(-3)] }]),
    undefined, warnings), []);
  assert.match([...warnings].join(), /target machine/);
});

void test("accepts the largest representable native lifetime endpoint", () => {
  const warnings = new Set<string>();

  assert.equal(readDebugVariables(debugVariables([{ start: 0xffffffff, length: 0,
    variableNumber: 0, location: varLoc.register, operands: [amd64Register.rcx] }]),
    machine.amd64, warnings)[0]?.endOffset, 0xffffffff);
  assert.deepEqual([...warnings], []);
});
