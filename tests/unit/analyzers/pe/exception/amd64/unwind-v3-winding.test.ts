import assert from "node:assert/strict";
import { test } from "node:test";
import { createV3WindingReader } from "../../../../../../analyzers/pe/exception/amd64/unwind-v3-winding.js";

// Byte encodings and operand scaling from the Microsoft V3 WOD reference.
// https://learn.microsoft.com/en-us/cpp/build/x64-unwind-information-v3#wod-encoding-reference
for (const [bytes, expected] of [
  [[0xfc], { opcode: "PUSH", register: 31 }],
  [[0xf7], { opcode: "PUSH_CONSECUTIVE_2", register: 30 }],
  [[0xe0, 0xff], { opcode: "PUSH2", register: 31, register2: 31 }],
  [[0x00, 0xff], { opcode: "SET_FPREG", register: 15, displacement: 240 }],
  [[0x08], { opcode: "ALLOC_SMALL", size: 8 }],
  [[0xf8], { opcode: "ALLOC_SMALL", size: 128 }],
  [[0x02, 0xff, 0xff], { opcode: "ALLOC_LARGE", size: 524280 }],
  [[0x01, 0xff, 0xff, 0xff, 0xff], { opcode: "ALLOC_HUGE", size: 4294967295 }],
  [[0xfe, 0xff, 0xff], { opcode: "SAVE_NONVOL", register: 31, displacement: 524280 }],
  [[0xfd, 0xff, 0xff, 0xff, 0xff], { opcode: "SAVE_NONVOL_FAR", register: 31, displacement: 4294967295 }],
  [[0xfa, 0xff, 0xff], { opcode: "SAVE_XMM128", register: 15, displacement: 1048560 }],
  [[0xf9, 0xff, 0xff, 0xff, 0xff], { opcode: "SAVE_XMM128_FAR", register: 15, displacement: 4294967295 }],
  [[0x03, 0xff], { opcode: "PUSH_CANONICAL_FRAME", frameType: 255 }],
  [[0x00, 0], { opcode: "SET_FPREG", register: 0, displacement: 0 }],
  [[0x02, 0, 0], { opcode: "ALLOC_LARGE", size: 0 }],
  [[0x01, 0, 0, 0, 0], { opcode: "ALLOC_HUGE", size: 0 }],
  [[0x06, 0, 0], { opcode: "SAVE_NONVOL", register: 0, displacement: 0 }],
  [[0x05, 0, 0, 0, 0], { opcode: "SAVE_NONVOL_FAR", register: 0, displacement: 0 }],
  [[0x0a, 0, 0], { opcode: "SAVE_XMM128", register: 0, displacement: 0 }],
  [[0x09, 0, 0, 0, 0], { opcode: "SAVE_XMM128_FAR", register: 0, displacement: 0 }],
  [[0x03, 0], { opcode: "PUSH_CANONICAL_FRAME", frameType: 0 }],
  [[0x20, 0], { opcode: "PUSH2", register: 0, register2: 0 }],
  [[0x07], { opcode: "PUSH_CONSECUTIVE_2", register: 0 }],
  [[0x02, 1, 2], { opcode: "ALLOC_LARGE", size: 4104 }],
  [[0x01, 1, 2, 3, 4], { opcode: "ALLOC_HUGE", size: 67305985 }],
  [[0x06, 1, 2], { opcode: "SAVE_NONVOL", register: 0, displacement: 4104 }],
  [[0x05, 1, 2, 3, 4], { opcode: "SAVE_NONVOL_FAR", register: 0, displacement: 67305985 }],
  [[0x0a, 1, 2], { opcode: "SAVE_XMM128", register: 0, displacement: 8208 }],
  [[0x09, 1, 2, 3, 4], { opcode: "SAVE_XMM128_FAR", register: 0, displacement: 67305985 }],
  [[0xa0, 0x1d], { opcode: "PUSH2", register: 22, register2: 3 }]
] as const) {
  void test(`V3 decodes ${expected.opcode} with its documented operands`, () => {
    const pool = Uint8Array.from(bytes);
    const issues: string[] = [];
    const operations = createV3WindingReader(new DataView(pool.buffer))(0, 1, issues);

    assert.deepEqual(operations, [expected]);
    assert.deepEqual(issues, []);
  });
}

for (const bytes of [[0xff], [0x10], [0x1b], [0x0b, 1, 2, 3, 4], [0x00], [0x01, 1, 2, 3], [0x02, 1],
  [0x03], [0xfd, 1, 2, 3], [0xfe, 1], [0xf9, 1, 2, 3], [0xfa, 1], [0x20]]) {
  void test(`V3 rejects an invalid or incomplete WOD ${bytes}`, () => {
    const issues: string[] = [];
    const operations = createV3WindingReader(new DataView(Uint8Array.from(bytes).buffer))(0, 1, issues);

    assert.deepEqual(operations, []);
    assert.deepEqual(issues, ["UNWIND_INFO v3 has an invalid or truncated WOD at pool byte 0."]);
  });
}

void test("V3 accepts adjacent operations when references visit the later record first", () => {
  const issues: string[] = [];
  const read = createV3WindingReader(new DataView(Uint8Array.of(2, 1, 0, 4).buffer));

  assert.deepEqual(read(3, 1, issues), [{ opcode: "PUSH", register: 0 }]);
  assert.deepEqual(read(0, 1, issues), [{ opcode: "ALLOC_LARGE", size: 8 }]);
  assert.deepEqual(issues, []);
});

void test("V3 accepts separate one-byte operations in reverse pool order", () => {
  const issues: string[] = [];
  const read = createV3WindingReader(new DataView(Uint8Array.of(4, 4, 4, 4).buffer));

  assert.deepEqual([3, 2, 1, 0].map(offset => read(offset, 1, issues)),
    Array.from({ length: 4 }, () => [{ opcode: "PUSH", register: 0 }]));
  assert.deepEqual(issues, []);
});

for (const count of [-1, 0.5, 32, Infinity, NaN]) {
  void test(`V3 rejects an invalid WOD count ${count}`, () => {
    const issues: string[] = [];
    const read = createV3WindingReader(new DataView(Uint8Array.of(4).buffer));

    assert.deepEqual(read(0, count, issues), []);
    assert.deepEqual(issues, ["UNWIND_INFO v3 has an invalid winding-operation count."]);
  });
}

for (const offset of [-1, 0.5, 1, Infinity, NaN]) {
  void test(`V3 rejects a WOD offset outside the pool ${offset}`, () => {
    const issues: string[] = [];
    const read = createV3WindingReader(new DataView(Uint8Array.of(4).buffer));

    assert.deepEqual(read(offset, 1, issues), []);
    assert.equal(issues.length, 1);
  });
}

void test("V3 caches shared operations and failures and retains a valid prefix", context => {
  const pool = new DataView(Uint8Array.of(4, 0x10).buffer);
  const calls = context.mock.method(pool, "getUint8");
  const read = createV3WindingReader(pool);
  const issues: string[] = [];
  const first = read(0, 2, issues);
  const second = read(0, 2, issues);

  assert.deepEqual(first, [{ opcode: "PUSH", register: 0 }]);
  assert.equal(first[0], second[0]);
  assert.equal(calls.mock.callCount(), 2);
  assert.equal(issues.length, 2);
});

void test("V3 empty operation lists do not consume padding or dereference a FirstOp", () => {
  const issues: string[] = [];
  const read = createV3WindingReader(new DataView(Uint8Array.of(0).buffer));

  assert.deepEqual(read(100, 0, issues), []);
  assert.deepEqual(issues, []);
});

void test("V3 respects a pool view's byte offset and supports 31 operations", () => {
  const bytes = Uint8Array.from([0xff, ...Array.from({ length: 31 }, () => 4), 0xff]);
  const issues: string[] = [];
  const operations = createV3WindingReader(new DataView(bytes.buffer, 1, 31))(0, 31, issues);

  assert.equal(operations.length, 31);
  assert.deepEqual(operations[30], { opcode: "PUSH", register: 0 });
  assert.deepEqual(issues, []);
});

for (const offsets of [[0, 1], [1, 0]] as const) {
  void test(`V3 rejects overlapping operation encodings referenced at ${offsets}`, () => {
    const issues: string[] = [];
    const read = createV3WindingReader(new DataView(Uint8Array.of(2, 4, 0).buffer));

    assert.equal(read(offsets[0], 1, issues).length, 1);
    assert.deepEqual(read(offsets[1], 1, issues), []);
    assert.equal(issues.length, 1);
  });
}
