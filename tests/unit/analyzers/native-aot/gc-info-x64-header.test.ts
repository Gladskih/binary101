import assert from "node:assert/strict";
import { test } from "node:test";
import { readX64GcHeader } from "../../../../analyzers/native-aot/gc-info-x64-header.js";
import { GcBitReader } from "../../../../analyzers/native-aot/gc-bit-reader.js";
import { GcInfoBitsFixture } from "../../../helpers/gc-info-bits-fixture.js";
import { GC_INFO_HEADER_FLAGS } from "../../../helpers/gc-info-wire-format.js";

void test("decodes slim v3/v4 headers and the implicit RBP frame register", () => {
  const modern = new GcInfoBitsFixture().slimX64V4HeaderWithFrameRegister(32).bytes();
  const legacy = new GcInfoBitsFixture().slimX64V3Header(2, 16).bytes();

  assert.deepEqual(readX64GcHeader(new GcBitReader(modern), 4),
    { header: { flags: 64, codeLength: 32, stackBaseRegister: 5 }, format: "slim" });
  assert.deepEqual(readX64GcHeader(new GcBitReader(legacy), 3),
    { header: { flags: 0, codeLength: 16, returnKind: 2 }, format: "slim" });
});

void test("decodes fat v4 cookie, generic context, frame register, EnC and reverse PInvoke", () => {
  // Named flags follow GcInfoHeaderFlags in the format source.
  const bytes = new GcInfoBitsFixture().fatX64V4Header(
    GC_INFO_HEADER_FLAGS.hasGsCookie | GC_INFO_HEADER_FLAGS.genericsContextThis |
      GC_INFO_HEADER_FLAGS.hasStackBaseRegister | GC_INFO_HEADER_FLAGS.hasEditAndContinueInfo |
      GC_INFO_HEADER_FLAGS.reversePInvokeFrame, 64)
    .x64CookieValidityRange(64, 4, 62).x64StackOffset(-8).x64StackOffset(-16)
    .x64FrameLayout(0, 8, -24, 16).bytes();

  assert.deepEqual(readX64GcHeader(new GcBitReader(bytes), 4), { format: "fat", header: {
    flags: 0x374, codeLength: 64, validRange: { startOffset: 4, endOffset: 62 },
    cookieStackOffset: -8, genericContextStackOffset: -16, stackBaseRegister: 5,
    editAndContinueBytes: 8, reversePInvokeStackOffset: -24, outgoingStackBytes: 16
  } });
});

void test("decodes v3 parent stack slots and generic-context prolog validity", () => {
  // v3 has a four-bit return kind in a fat header; generic-context flags select a
  // prolog-only validity start, followed by parent and generic stack slots.
  const flags = GC_INFO_HEADER_FLAGS.hasPspSymbol | GC_INFO_HEADER_FLAGS.genericsContextThis;
  const bytes = new GcInfoBitsFixture().fatX64V3Header(flags, 1, 32)
    .x64PrologValidityStart(3).x64StackOffset(-8).x64StackOffset(-16)
    .x64OutgoingStackBytes(0).bytes();

  assert.deepEqual(readX64GcHeader(new GcBitReader(bytes), 3).header, {
    flags, returnKind: 1, codeLength: 32, validRange: { startOffset: 3, endOffset: 4 },
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
  // 2**28 scaled by eight is Int32.MinValue; the paired case crosses that lower
  // boundary by one before scaling.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/gcinfodecoder.cpp
  assert.deepEqual(readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(0, 10).field(0, 4).unsigned(2, 8).unsigned(0, 3).bytes()), 3).header,
  { flags: 0, returnKind: 0, codeLength: 2, outgoingStackBytes: 0 });
  assert.equal(readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(512, 10).unsigned(32, 8).signed(-(2 ** 28), 6).unsigned(0, 3).bytes()), 4)
    .header.reversePInvokeStackOffset, -2147483648);
  assert.throws(() => readX64GcHeader(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(512, 10).unsigned(32, 8).signed(-(2 ** 28) - 1, 6).bytes()), 4), /Int32/);
});
