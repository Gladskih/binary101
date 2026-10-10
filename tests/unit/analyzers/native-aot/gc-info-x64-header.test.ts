import assert from "node:assert/strict";
import { test } from "node:test";
import { readX64GcHeader } from "../../../../analyzers/native-aot/gc-info-x64-header.js";
import { GcBitReader } from "../../../../analyzers/native-aot/gc-bit-reader.js";
import { GcInfoBitsFixture } from "../../../helpers/gc-info-bits-fixture.js";

void test("decodes slim v3/v4 headers and the implicit RBP frame register", () => {
  const modern = new GcInfoBitsFixture().field(0, 1).field(1, 1).unsigned(32, 8).bytes();
  const legacy = new GcInfoBitsFixture().field(0, 1).field(0, 1).field(2, 2).unsigned(16, 8).bytes();

  assert.deepEqual(readX64GcHeader(new GcBitReader(modern), 4),
    { header: { flags: 64, codeLength: 32, stackBaseRegister: 5 }, format: "slim" });
  assert.deepEqual(readX64GcHeader(new GcBitReader(legacy), 3),
    { header: { flags: 0, codeLength: 16, returnKind: 2 }, format: "slim" });
});

void test("decodes fat v4 cookie, generic context, frame register, EnC and reverse PInvoke", () => {
  const bytes = new GcInfoBitsFixture().field(1, 1).field(0x374, 10).unsigned(64, 8)
    .unsigned(3, 5).unsigned(2, 3).signed(-1, 6).signed(-2, 6).unsigned(0, 3)
    .unsigned(8, 4).signed(-3, 6).unsigned(2, 3).bytes();

  assert.deepEqual(readX64GcHeader(new GcBitReader(bytes), 4), { format: "fat", header: {
    flags: 0x374, codeLength: 64, validRange: { startOffset: 4, endOffset: 62 },
    cookieStackOffset: -8, genericContextStackOffset: -16, stackBaseRegister: 5,
    editAndContinueBytes: 8, reversePInvokeStackOffset: -24, outgoingStackBytes: 16
  } });
});

void test("decodes v3 parent stack slots and generic-context prolog validity", () => {
  const bytes = new GcInfoBitsFixture().field(1, 1).field(0x18, 10).field(1, 4)
    .unsigned(32, 8).unsigned(2, 5).signed(-1, 6).signed(-2, 6).unsigned(0, 3).bytes();

  assert.deepEqual(readX64GcHeader(new GcBitReader(bytes), 3).header, {
    flags: 0x18, returnKind: 1, codeLength: 32, validRange: { startOffset: 3, endOffset: 4 },
    parentStackOffset: -8, genericContextStackOffset: -16, outgoingStackBytes: 0
  });
});

void test("rejects reserved flags and invalid cookie/prolog ranges", () => {
  assert.throws(() => readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(2, 10).unsigned(1, 8).bytes()), 4), /reserved/);
  assert.throws(() => readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(4, 10).unsigned(2, 8).unsigned(3, 5).unsigned(0, 3).bytes()), 4), /range/);
});

void test("rejects invalid frame registers, zero-length methods and scaled offset overflow", () => {
  // AMD64 normalizes the frame register with XOR 5: encoded 1 means forbidden RSP.
  assert.throws(() => readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(64, 10).unsigned(32, 8).unsigned(1, 3).bytes()), 4), /register/);
  assert.throws(() => readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(64, 10).unsigned(32, 8).unsigned(16, 3).bytes()), 4), /register/);
  assert.throws(() => readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(0, 2).unsigned(0, 8).bytes()), 4), /length/);
  assert.throws(() => readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(512, 10).unsigned(32, 8).signed(2 ** 28, 6).bytes()), 4), /Int32/);
  assert.throws(() => readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(0, 10).unsigned(32, 8).unsigned(2 ** 29, 3).bytes()), 4), /UInt32/);
});

void test("checks validity-range boundaries and distinguishes v3/v4 parent-slot flags", () => {
  assert.throws(() => readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(4, 10).unsigned(2, 8).unsigned(1, 5).unsigned(0, 3).bytes()), 4), /range/);
  assert.throws(() => readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(16, 10).unsigned(2, 8).unsigned(1, 5).bytes()), 4), /range/);
  assert.throws(() => readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(8, 10).unsigned(2, 8).bytes()), 4), /reserved/);
  assert.deepEqual(readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(0, 10).field(0, 4).unsigned(2, 8).unsigned(0, 3).bytes()), 3).header,
  { flags: 0, returnKind: 0, codeLength: 2, outgoingStackBytes: 0 });
  assert.equal(readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(512, 10).unsigned(32, 8).signed(-(2 ** 28), 6).unsigned(0, 3).bytes()), 4)
    .header.reversePInvokeStackOffset, -2147483648);
  assert.throws(() => readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(512, 10).unsigned(32, 8).signed(-(2 ** 28) - 1, 6).bytes()), 4), /Int32/);
});
