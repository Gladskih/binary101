import assert from "node:assert/strict";
import { test } from "node:test";
import { parseIa64Descriptors } from "../../../../../analyzers/pe/exception/ia64-descriptors.js";
import { MockFile } from "../../../../helpers/mock-file.js";

// Intel 245358-003, appendix B, defines these R/P/B/X byte encodings.
// https://github.com/libunwind/libunwind/blob/v1.8.1/src/ia64/unwind_decoder.h

for (const [name, bytes, counts] of [
  ["R1 prologue, body and zero-length padding", [3, 0x25, 0],
    { "Prologue regions": 1, "Body regions": 1, "Empty prologues / padding": 1 }],
  ["R2 saved-register prologue", [0x47, 0xa0, 0x82, 1], { "Prologue regions": 1 }],
  ["R3 long regions", [0x60, 0, 0x61, 0x80, 1], { "Empty prologues / padding": 1, "Body regions": 1 }],
  ["P1, P2, P3, P5, P6 register rules", [1, 0x81, 0xa1, 0x20, 0xb5, 0x80, 0xb9, 0x10, 0, 1, 0xc1, 0xd1],
    { "Prologue regions": 1, "Register rules": 6 }],
  ["P4 instruction spill schedules", [5, 0xb8, 0xff, 0], { "Prologue regions": 1, "Spill schedules": 1 }],
  ["zero-length P4", [0, 0xb8], { "Empty prologues / padding": 1, "Spill schedules": 1 }],
  ["P7 fixed, variable, spill-base and register rules", [1, 0xe0, 0, 3, 0xe1, 0, 0xe2, 0, 0xef, 0],
    { "Prologue regions": 1, "Fixed stack allocations": 1, "Variable stack allocations": 1,
      "Spill-base changes": 1, "Register rules": 1 }],
  ["P8, P9 and P10", [1, 0xf0, 19, 0, 0xf1, 1, 32, 0xff, 1, 0],
    { "Prologue regions": 1, "Register rules": 2, "ABI context records": 1 }],
  ["first P1, P2, P3, P6 and P8 encodings", [1, 0x80, 0xa0, 0x20, 0xb0, 0x20, 0xc0, 0xf0, 1, 0],
    { "Prologue regions": 1, "Register rules": 5 }],
  ["upper P2 register-mask bits", [1, 0xaf, 0x20], { "Prologue regions": 1, "Register rules": 1 }],
  ["isolated spill-base change", [1, 0xe2, 0], { "Prologue regions": 1, "Spill-base changes": 1 }],
  ["isolated B4 label", [0x21, 0xf0, 1], { "Body regions": 1, "Saved-state labels": 1 }],
  ["isolated B4 copy", [0x21, 0xf8, 1], { "Body regions": 1, "Saved-state copies": 1 }],
  ["B1, B2, B3 and B4", [0x21, 0x81, 0xa1, 0xc0, 0, 0xe0, 0, 0, 0xf0, 0x80, 1, 0xf8, 0x81, 1],
    { "Body regions": 1, "Saved-state labels": 2, "Saved-state copies": 2, "Epilogues": 2 }],
  ["X1 through X4 in a prologue", [1, 0xf9, 4, 0, 0, 0xfa, 4, 32, 0,
    0xfb, 1, 4, 0, 0, 0xfc, 1, 4, 32, 0], { "Prologue regions": 1, "Register rules": 4 }],
  ["X1 through X4 in a body", [0x21, 0xf9, 4, 0, 0, 0xfa, 4, 0, 0,
    0xfb, 1, 4, 0, 0, 0xfc, 1, 4, 0, 0], { "Body regions": 1, "Register rules": 4 }]
] as const) {
  void test(`IA64 descriptors decode ${name}`, async () => {
    const parsed = await parseIa64Descriptors(new MockFile(Uint8Array.from(bytes)));

    assert.deepEqual(parsed.counts, counts);
    assert.deepEqual(parsed.issues, []);
  });
}

void test("IA64 records the largest fixed stack in bytes instead of allocation units", async () => {
  const parsed = await parseIa64Descriptors(new MockFile(Uint8Array.from([1, 0xe0, 0, 3, 0xe0, 0, 1])));

  assert.equal(parsed.maximumFixedStackBytes, 48);
  assert.equal(parsed.counts["Fixed stack allocations"], 2);
});

for (const bytes of [[0x48], [0x62, 0], [1, 0xba], [1, 0xb6, 0], [1, 0xb6, 0x80], [1, 0xf0, 0, 0],
  [1, 0xf0, 20, 0], [1, 0xf2], [0x21, 0xe1, 0, 0], [0x21, 0xf1], [0x21, 0xff]]) {
  void test(`IA64 stops at unknown or reserved descriptor ${bytes.join(",")}`, async () => {
    const parsed = await parseIa64Descriptors(new MockFile(Uint8Array.from(bytes)));

    assert.match(parsed.issues.join(" | "), /reserved/);
  });
}

for (const bytes of [[0x40], [0x60, 0x80], [1, 0xa0], [1, 0xb0], [5, 0xb8, 0], [1, 0xb9, 0, 0],
  [1, 0xe0, 0], [1, 0xf0], [1, 0xf1, 0], [1, 0xff, 0], [1, 0xf9], [1, 0xfa, 0],
  [1, 0xfb, 0, 0, 0], [1, 0xfc, 0, 0], [0x21, 0xc0], [0x21, 0xe0, 0], [0x21, 0xf0]]) {
  void test(`IA64 bounds truncated descriptor ${bytes.join(",")}`, async () => {
    const parsed = await parseIa64Descriptors(new MockFile(Uint8Array.from(bytes)));

    assert.match(parsed.issues.join(" | "), /truncated/);
    assert.equal(parsed.maximumFixedStackBytes, undefined);
    assert.equal(Object.values(parsed.counts).reduce((sum, count) => sum + count, 0),
      Number(bytes[0] === 1 || bytes[0] === 5 || bytes[0] === 0x21));
  });
}

void test("IA64 rejects descriptors without a region header", async () => {
  const parsed = await parseIa64Descriptors(new MockFile(Uint8Array.from([0x81])));

  assert.match(parsed.issues[0]!, /precedes its region header/);
  assert.deepEqual(parsed.counts, {});
});

void test("IA64 streams operands across bounded read windows", async () => {
  const bytes = new Uint8Array(65539);
  bytes.set([0x40, 32, 3, 0x81], 65535);
  const file = new MockFile(bytes);
  const reads: [number, number][] = [];
  const parsed = await parseIa64Descriptors({ size: file.size, read: (offset, size) => file.read(offset, size),
    readBytes: (offset, size) => { reads.push([offset, size]); return file.readBytes(offset, size); } });

  assert.deepEqual(parsed.issues, []);
  assert.deepEqual(parsed.counts, { "Empty prologues / padding": 65535, "Prologue regions": 1, "Register rules": 1 });
  assert.deepEqual(reads, [[0, 65536], [65536, 3]]);
});

void test("IA64 preserves valid records when a physical read returns a shorter prefix", async () => {
  const file = new MockFile(Uint8Array.from([1, 0xb8]));
  const parsed = await parseIa64Descriptors({ size: 3,
    read: (offset, size) => file.read(offset, size), readBytes: (offset, size) => file.readBytes(offset, size) });

  assert.deepEqual(parsed.counts, { "Prologue regions": 1 });
  assert.match(parsed.issues[0]!, /truncated/);
});

void test("IA64 handles empty physical reads and invalid source sizes", async () => {
  const file = new MockFile(new Uint8Array(0));
  const empty = await parseIa64Descriptors(file);
  const short = await parseIa64Descriptors({ size: 1,
    read: file.read.bind(file), readBytes: file.readBytes.bind(file) });
  const invalid = await parseIa64Descriptors({ size: -1,
    read: file.read.bind(file), readBytes: file.readBytes.bind(file) });
  const fractional = await parseIa64Descriptors({ size: 0.5,
    read: file.read.bind(file), readBytes: file.readBytes.bind(file) });

  assert.deepEqual(empty, { counts: {}, issues: [] });
  assert.match(short.issues[0]!, /truncated/);
  assert.deepEqual(short.counts, {});
  assert.match(invalid.issues[0]!, /invalid/);
  assert.match(fractional.issues[0]!, /invalid/);
});

for (const operand of [[...new Array<number>(10).fill(0x80), 0], [...new Array<number>(9).fill(0xff), 2]]) {
  void test("IA64 rejects ULEB128 operands wider than the 64-bit target", async () => {
    const parsed = await parseIa64Descriptors(new MockFile(Uint8Array.from([0x60, ...operand])));

    assert.deepEqual(parsed.counts, {});
    assert.match(parsed.issues[0]!, /exceeds 64 bits/);
  });
}

void test("IA64 does not round large fixed-stack sizes or enormous spill-mask lengths", async () => {
  const maximum = [...new Array<number>(9).fill(0xff), 1]; // UINT64_MAX in ULEB128.
  const stack = await parseIa64Descriptors(new MockFile(Uint8Array.from([1, 0xe0, 0, ...maximum, 0x25])));
  const mask = await parseIa64Descriptors(new MockFile(Uint8Array.from([0x60, ...maximum, 0xb8])));

  assert.equal(stack.maximumFixedStackBytes, undefined);
  assert.equal(stack.counts["Body regions"], 1);
  assert.match(stack.issues[0]!, /exact numeric range/);
  assert.match(mask.issues[0]!, /truncated/);
});

void test("IA64 avoids reading beyond EOF for a truncated operand", async () => {
  const file = new MockFile(Uint8Array.from([0x40]));
  const reads: [number, number][] = [];
  const parsed = await parseIa64Descriptors({ size: file.size, read: file.read.bind(file),
    readBytes: (offset, size) => { reads.push([offset, size]); return file.readBytes(offset, size); } });

  assert.match(parsed.issues[0]!, /truncated/);
  assert.deepEqual(reads, [[0, 1]]);
});

void test("IA64 retains every complete record from a short physical window", async () => {
  const file = new MockFile(Uint8Array.from([1, 0x81]));
  const parsed = await parseIa64Descriptors({ size: 3,
    read: file.read.bind(file), readBytes: file.readBytes.bind(file) });

  assert.deepEqual(parsed.counts, { "Prologue regions": 1, "Register rules": 1 });
  assert.match(parsed.issues[0]!, /truncated/);
});

void test("IA64 stops fetching descriptor windows after a framing error", async () => {
  const bytes = new Uint8Array(65537);
  bytes.set([1, 0xba]); // Unknown prologue encoding; later bytes cannot be resynchronized.
  const file = new MockFile(bytes);
  const reads: number[] = [];
  const parsed = await parseIa64Descriptors({ size: file.size, read: file.read.bind(file),
    readBytes: (offset, size) => { reads.push(offset); return file.readBytes(offset, size); } });

  assert.deepEqual(parsed.counts, { "Prologue regions": 1 });
  assert.match(parsed.issues[0]!, /reserved/);
  assert.deepEqual(reads, [0]);
});
