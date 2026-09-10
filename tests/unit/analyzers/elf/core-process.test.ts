import assert from "node:assert/strict";
import { test } from "node:test";
import { ElfCoreNoteReader } from "../../../../analyzers/elf/core-note-reader.js";
import { parseElfCoreProcess, parseElfCoreStatus } from "../../../../analyzers/elf/core-process.js";

const status = () => {
  const bytes = new Uint8Array(336);
  const view = new DataView(bytes.buffer);
  view.setInt32(4, -6, true);
  view.setInt32(32, 1234, true);
  view.setBigUint64(240, 0x123456789abcdef0n, true); // x86-64 RIP: common header 112 + 16*8.
  view.setInt32(328, 1, true);
  return bytes;
};

void test("reads Linux x86-64 status signal, PID and general registers", () => {
  const note = parseElfCoreStatus(new ElfCoreNoteReader(status(), 8, "little"), 62);
  assert.equal(note.fields.find(field => field.name === "Code")?.value, -6n);
  assert.equal(note.fields.find(field => field.name === "PID")?.value, 1234n);
  assert.equal(note.registers?.find(field => field.name === "rip")?.value, 0x123456789abcdef0n);
  assert.equal(note.fields.find(field => field.name === "FP valid")?.value, 1n);
  assert.deepEqual(note.issues, []);
  assert.deepEqual(note.fields.map(field => field.name), ["Signal", "Code", "Errno",
    "Current signal", "Pending signals", "Held signals", "PID", "Parent PID", "Process group",
    "Session", "User seconds", "User microseconds", "System seconds", "System microseconds",
    "Child user seconds", "Child user microseconds", "Child system seconds",
    "Child system microseconds", "FP valid"]);
});

void test("uses distinct i386 and AArch64 register layouts", () => {
  const x86 = parseElfCoreStatus(new ElfCoreNoteReader(new Uint8Array(144), 4, "little"), 3);
  assert.equal(x86.registers?.length, 17);
  assert.equal(x86.registers?.[12]?.name, "eip");
  assert.deepEqual(x86.registers?.map(register => register.name),
    "ebx ecx edx esi edi ebp eax ds es fs gs orig_eax eip cs eflags esp ss".split(" "));
  const arm = parseElfCoreStatus(new ElfCoreNoteReader(new Uint8Array(392), 8, "big"), 183);
  assert.equal(arm.registers?.length, 34);
  assert.equal(arm.registers?.[32]?.name, "pc");
  assert.deepEqual(arm.registers?.map(register => register.name),
    [...Array.from({ length: 31 }, (_, index) => `x${index}`), "sp", "pc", "pstate"]);
  assert.deepEqual(arm.issues, []);
});

void test("retains every x86-64 general register in Linux ABI order", () => {
  const bytes = status();
  const view = new DataView(bytes.buffer);
  Array.from({ length: 27 }, (_, index) => index + 1).forEach((value, index) =>
    view.setBigUint64(112 + index * 8, BigInt(value), true));
  assert.deepEqual(parseElfCoreStatus(new ElfCoreNoteReader(bytes, 8, "little"), 62).registers,
    "r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs"
      .split(" ").map((name, index) => ({ name, value: BigInt(index + 1) })));
});

void test("does not infer unsupported or mismatched register ABIs", () => {
  const note = parseElfCoreStatus(new ElfCoreNoteReader(status(), 4, "little"), 62);
  assert.equal(note.registers, undefined);
  assert.match(note.issues.join(" "), /Unsupported/);
});

void test("reads i386 process identifiers as 16-bit UID/GID and signed nice", () => {
  const bytes = new Uint8Array(124);
  const view = new DataView(bytes.buffer);
  view.setInt8(3, -5);
  view.setUint16(8, 1000, true);
  view.setUint16(10, 1001, true);
  view.setInt32(12, 1234, true);
  bytes.set(new TextEncoder().encode("prog\0"), 28);
  bytes.set(new TextEncoder().encode("prog arg\0"), 44);
  const note = parseElfCoreProcess(new ElfCoreNoteReader(bytes, 4, "little"), 3);
  assert.equal(note.fields.find(field => field.name === "UID")?.value, 1000n);
  assert.equal(note.fields.find(field => field.name === "GID")?.value, 1001n);
  assert.equal(note.fields.find(field => field.name === "PID")?.value, 1234n);
  assert.equal(note.fields.find(field => field.name === "Nice")?.value, -5n);
  assert.equal(note.fields.find(field => field.name === "Executable")?.value, "prog");
  assert.equal(note.fields.find(field => field.name === "Arguments")?.value, "prog arg");
  assert.deepEqual(note.fields.map(field => field.name), ["State", "State character", "Zombie",
    "Nice", "Flags", "UID", "GID", "PID", "Parent PID", "Process group", "Session",
    "Executable", "Arguments"]);
});

void test("reads LP64 process data and reports incomplete or unsupported data", () => {
  const bytes = new Uint8Array(136);
  new DataView(bytes.buffer).setUint32(16, 70000);
  assert.equal(parseElfCoreProcess(new ElfCoreNoteReader(bytes, 8, "big"), 183)
    .fields.find(field => field.name === "UID")?.value, 70000n);
  assert.match(parseElfCoreProcess(new ElfCoreNoteReader(bytes.subarray(0, 2), 8, "big"), 62)
    .issues.join(" "), /truncated/);
  assert.match(parseElfCoreProcess(new ElfCoreNoteReader(bytes, 8, "big"), 999)
    .issues.join(" "), /Unsupported/);
  assert.deepEqual(parseElfCoreProcess(new ElfCoreNoteReader(bytes.subarray(0, 0), 8, "big"), 62).fields, []);
});

void test("keeps each process accounting timeval in its own slot", () => {
  const bytes = status();
  const view = new DataView(bytes.buffer);
  Array.from({ length: 8 }, (_, index) => index + 1).forEach((value, index) =>
    view.setBigUint64(48 + index * 8, BigInt(value), true));
  const note = parseElfCoreStatus(new ElfCoreNoteReader(bytes, 8, "little"), 62);
  assert.deepEqual(note.fields.slice(10, 18).map(field => field.value), [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]);
});
