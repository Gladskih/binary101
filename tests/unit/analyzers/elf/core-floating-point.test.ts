import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfCoreNote } from "../../../../analyzers/elf/core-notes.js";

void test("decodes x86-64 FXSAVE and AArch64 FPSIMD register storage", () => {
  const bytes = new Uint8Array(528);
  bytes[160] = 1; // FXSAVE xmm0 starts at byte 160 (Linux user_64.h).
  assert.equal(parseElfCoreNote(bytes.subarray(0, 512), 2, 8, "little", 62)
    .registers?.find(item => item.name === "xmm0")?.value, 1n);
  bytes[0] = 7;
  assert.equal(parseElfCoreNote(bytes, 2, 8, "little", 183).registers?.[0]?.value, 7n);
});

void test("reports truncated floating point state and unknown ABI", () => {
  assert.match(parseElfCoreNote(new Uint8Array(1), 2, 8, "little", 62).issues.join(" "), /truncated/);
  assert.match(parseElfCoreNote(new Uint8Array(512), 2, 8, "little", 999).issues.join(" "), /Unsupported/);
});

void test("reads XSAVE feature masks without guessing compacted component offsets", () => {
  const bytes = new Uint8Array(576);
  new DataView(bytes.buffer).setBigUint64(520, 1n << 63n, true);
  const note = parseElfCoreNote(bytes, 0x202, 8, "little", 62);
  assert.equal(note.fields.find(item => item.name === "XCOMP_BV")?.value, 1n << 63n);
  assert.match(note.issues.join(" "), /component/);
});

void test("rejects mismatched XSAVE ABI and a short XSAVE header", () => {
  assert.match(parseElfCoreNote(new Uint8Array(576), 0x202, 4, "little", 62)
    .issues.join(" "), /Unsupported/);
  assert.match(parseElfCoreNote(new Uint8Array(512), 0x202, 8, "little", 62)
    .issues.join(" "), /truncated/);
});

const fxsave = () => {
  const bytes = new Uint8Array(512);
  const view = new DataView(bytes.buffer);
  [1, 2, 3, 4].forEach((value, index) => view.setUint16(index * 2, value, true));
  view.setBigUint64(8, 5n, true);
  view.setBigUint64(16, 6n, true);
  view.setUint32(24, 7, true);
  view.setUint32(28, 8, true);
  Array.from({ length: 24 }, (_, index) => index + 9).forEach((value, index) =>
    view.setBigUint64(32 + index * 16, BigInt(value), true));
  return bytes;
};

void test("retains every FXSAVE environment field and register slot independently", () => {
  const note = parseElfCoreNote(fxsave(), 2, 8, "little", 62);
  assert.deepEqual(note.fields, ["FCW", "FSW", "FTW", "FOP", "Instruction pointer",
    "Data pointer", "MXCSR", "MXCSR mask"].map((name, index) => ({ name, value: BigInt(index + 1) })));
  assert.deepEqual(note.registers, [...Array.from({ length: 8 }, (_, index) => `st${index}`),
    ...Array.from({ length: 16 }, (_, index) => `xmm${index}`)]
    .map((name, index) => ({ name, value: BigInt(index + 9) })));
  assert.deepEqual(note.issues, []);
});

void test("retains all AArch64 vectors and floating point control registers", () => {
  const bytes = new Uint8Array(528);
  const view = new DataView(bytes.buffer);
  Array.from({ length: 32 }, (_, index) => index + 1).forEach((value, index) =>
    view.setBigUint64(index * 16, BigInt(value), true));
  view.setUint32(512, 33, true);
  view.setUint32(516, 34, true);
  const note = parseElfCoreNote(bytes, 2, 8, "little", 183);
  assert.deepEqual(note.registers, Array.from({ length: 32 }, (_, index) =>
    ({ name: `v${index}`, value: BigInt(index + 1) })));
  assert.deepEqual(note.fields, [{ name: "FPSR", value: 33n }, { name: "FPCR", value: 34n }]);
  assert.deepEqual(note.issues, []);
});
