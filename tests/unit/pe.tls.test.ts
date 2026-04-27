"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseTlsDirectory32, parseTlsDirectory64 } from "../../analyzers/pe/directories/tls.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const IMAGE_TLS_DIRECTORY32_SIZE = 0x18; // IMAGE_TLS_DIRECTORY32
// Microsoft PE format, "The TLS Directory": PE32+ TLS directory is 0x28 bytes.
const IMAGE_TLS_DIRECTORY64_SIZE = 0x28;
const TLS_CALLBACK_ENTRY_SIZE32 = Uint32Array.BYTES_PER_ELEMENT; // One 32-bit callback pointer

void test("parseTlsDirectory handles 32-bit and 64-bit callbacks", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  const tlsRva = 0x20;
  dv.setUint32(tlsRva + 0, 0x10, true);
  dv.setUint32(tlsRva + 4, 0x20, true);
  dv.setUint32(tlsRva + 8, 0x30, true);
  dv.setUint32(tlsRva + 12, 0x40, true);
  dv.setUint32(tlsRva + 16, 4, true);
  dv.setUint32(tlsRva + 20, 0, true);
  dv.setUint32(0x40, 0x1111, true); // Callback VA/RVA chosen to be obviously non-zero and easy to assert.
  dv.setUint32(0x44, 0);

  const tls = expectDefined(await parseTlsDirectory32(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    value => value,
    0n
  ));
  assert.equal(tls.CallbackCount, 1);
  assert.deepEqual(tls.CallbackRvas, [0x1111]);
  assert.equal(tls.parsed, true);

  const bytes64 = new Uint8Array(512).fill(0);
  const dv64 = new DataView(bytes64.buffer);
  dv64.setBigUint64(0x00, 0x100n, true);
  dv64.setBigUint64(0x08, 0x200n, true);
  dv64.setBigUint64(0x10, 0x300n, true);
  dv64.setBigUint64(0x18, 0x80n, true);
  dv64.setUint32(0x20, 8, true);
  dv64.setUint32(0x24, 0, true);
  dv64.setBigUint64(0x80, 0x7000n, true);
  dv64.setBigUint64(0x88, 0n, true);

  const tls64 = expectDefined(await parseTlsDirectory64(
    new MockFile(bytes64),
    [{ name: "TLS", rva: 0x10, size: IMAGE_TLS_DIRECTORY64_SIZE }],
    value => (value === 0x10 ? 0 : value),
    0n
  ));
  assert.equal(tls64.CallbackCount, 1);
  assert.deepEqual(tls64.CallbackRvas, [0x7000]);
  assert.equal(tls64.parsed, true);
});

void test("parseTlsDirectory returns null when the TLS data directory is absent", async () => {
  const file = new MockFile(new Uint8Array(16));
  assert.equal(await parseTlsDirectory32(file, [], value => value, 0n), null);
});

void test("parseTlsDirectory64 accepts the spec-sized TLS directory header", async () => {
  const tlsRva = 0x20;
  const bytes = new Uint8Array(tlsRva + 0x28).fill(0);
  const dv = new DataView(bytes.buffer);
  // Microsoft PE format, "The TLS Directory": Characteristics is at PE32+
  // offset 36 with size 4, so a complete PE32+ TLS directory is 0x28 bytes.
  dv.setBigUint64(tlsRva, 0x1800n, true);
  dv.setBigUint64(tlsRva + 8, 0x1810n, true);
  dv.setBigUint64(tlsRva + 16, 0x1820n, true);
  dv.setBigUint64(tlsRva + 24, 0n, true);
  dv.setUint32(tlsRva + 32, 4, true);
  dv.setUint32(tlsRva + 36, 0, true);

  const tls = expectDefined(await parseTlsDirectory64(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: 0x28 }],
    value => value,
    0n
  ));

  assert.equal(tls.parsed, true);
  assert.equal(tls.SizeOfZeroFill, 4);
  assert.equal(BigInt(tls.StartAddressOfRawData), 0x1800n);
});

void test("parseTlsDirectory preserves declared but unmapped TLS directories with warnings", async () => {
  const file = new MockFile(new Uint8Array(16));
  const tls = expectDefined(await parseTlsDirectory32(
    file,
    [{ name: "TLS", rva: 0x20, size: 0x18 }],
    () => null,
    0n
  ));

  assert.equal(tls.parsed, false);
  assert.ok(tls.warnings?.some(warning => /could not be mapped/i.test(warning)));
});

void test("parseTlsDirectory preserves truncated TLS directory headers with warnings", async () => {
  const tlsRva = 0x20;
  const truncated32 = new Uint8Array(tlsRva + 0x10).fill(0);
  const tls32 = expectDefined(await parseTlsDirectory32(
    new MockFile(truncated32),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY32_SIZE }],
    value => value,
    0n
  ));
  assert.equal(tls32.parsed, false);
  assert.ok(tls32.warnings?.some(warning => /truncated/i.test(warning)));

  const truncated64 = new Uint8Array(tlsRva + 0x20).fill(0);
  const tls64 = expectDefined(await parseTlsDirectory64(
    new MockFile(truncated64),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY64_SIZE }],
    value => value,
    0n
  ));
  assert.equal(tls64.parsed, false);
  assert.ok(tls64.warnings?.some(warning => /truncated/i.test(warning)));
});

void test("parseTlsDirectory warns when the declared data-directory size is too small for a TLS header", async () => {
  const tlsRva = IMAGE_TLS_DIRECTORY32_SIZE;
  const bytes32 = new Uint8Array(tlsRva + IMAGE_TLS_DIRECTORY32_SIZE).fill(0);
  const dv32 = new DataView(bytes32.buffer);
  // IMAGE_TLS_DIRECTORY32 is 0x18 bytes, so any smaller declared directory cannot describe a valid header.
  dv32.setUint32(tlsRva + 12, 0x40, true);
  const tls32 = expectDefined(await parseTlsDirectory32(
    new MockFile(bytes32),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY32_SIZE - 1 }],
    value => value,
    0n
  ));
  assert.equal(tls32.parsed, false);
  assert.ok(tls32.warnings?.some(warning => /smaller than the 32-bit TLS header size/i.test(warning)));

  const bytes64 = new Uint8Array(tlsRva + IMAGE_TLS_DIRECTORY64_SIZE).fill(0);
  const dv64 = new DataView(bytes64.buffer);
  // IMAGE_TLS_DIRECTORY64 is 0x30 bytes, so any smaller declared directory cannot describe a valid header.
  dv64.setBigUint64(tlsRva + 24, 0x80n, true);
  const tls64 = expectDefined(await parseTlsDirectory64(
    new MockFile(bytes64),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY64_SIZE - 1 }],
    value => value,
    0n
  ));
  assert.equal(tls64.parsed, false);
  assert.ok(tls64.warnings?.some(warning => /smaller than the 64-bit TLS header size/i.test(warning)));
});

void test(
  "parseTlsDirectory64 preserves 64-bit VA fields beyond Number.MAX_SAFE_INTEGER",
  async () => {
  const tlsRva = 0x20;
  const bytes = new Uint8Array(tlsRva + IMAGE_TLS_DIRECTORY64_SIZE).fill(0);
  const dv = new DataView(bytes.buffer);
  // 0x0020000000000001n is 2^53 + 1.
  // That is the first unsigned integer JS cannot represent exactly as Number.
  const firstUnsafeU64 = 0x0020000000000001n;
  const secondUnsafeU64 = 0x0020000000000003n;
  const thirdUnsafeU64 = 0x0020000000000005n;
  // PE format: IMAGE_TLS_DIRECTORY64 stores these fields as 64-bit VAs.
  dv.setBigUint64(tlsRva + 0x00, firstUnsafeU64, true);
  dv.setBigUint64(tlsRva + 0x08, secondUnsafeU64, true);
  dv.setBigUint64(tlsRva + 0x10, thirdUnsafeU64, true);
  dv.setBigUint64(tlsRva + 0x18, 0n, true);

  const tls = expectDefined(await parseTlsDirectory64(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY64_SIZE }],
    value => value,
    0n
  ));

  assert.equal(BigInt(tls.StartAddressOfRawData), firstUnsafeU64);
  assert.equal(BigInt(tls.EndAddressOfRawData), secondUnsafeU64);
  assert.equal(BigInt(tls.AddressOfIndex), thirdUnsafeU64);
  }
);

void test("parseTlsDirectory skips invalid callback pointers and tolerates out-of-range callback tables", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  const tlsRva = 0x20;
  dv.setUint32(tlsRva + 12, 0x2040, true);
  dv.setUint32(0x40, 0x1000, true);
  dv.setUint32(0x44, 0, true);

  const tls = expectDefined(await parseTlsDirectory32(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    value => value,
    0x2000n
  ));
  assert.equal(tls.CallbackCount, 0);
  assert.deepEqual(tls.CallbackRvas, []);
  assert.ok(tls.warnings?.some(warning => /not a valid VA/i.test(warning)));

  const bytesOutOfRange = new Uint8Array(64).fill(0);
  const dvOutOfRange = new DataView(bytesOutOfRange.buffer);
  dvOutOfRange.setUint32(tlsRva + 12, 0x1000, true);
  const rvaToOff = (rva: number): number => (rva === tlsRva ? tlsRva : bytesOutOfRange.length + 4);
  const tlsOutOfRange = expectDefined(await parseTlsDirectory32(
    new MockFile(bytesOutOfRange),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    rvaToOff,
    0n
  ));
  assert.equal(tlsOutOfRange.CallbackCount, 0);
  assert.deepEqual(tlsOutOfRange.CallbackRvas, []);
  assert.ok(tlsOutOfRange.warnings?.some(warning => /could not be mapped|truncated or unmapped/i.test(warning)));
});

void test("parseTlsDirectory does not read callback slots past an rvaToOff gap", async () => {
  const tlsRva = IMAGE_TLS_DIRECTORY32_SIZE;
  const callbackTableRva = tlsRva + IMAGE_TLS_DIRECTORY32_SIZE;
  const firstCallbackRva = 0x2000;
  const secondCallbackRva = firstCallbackRva + 0x1000;
  const bytes = new Uint8Array(callbackTableRva + TLS_CALLBACK_ENTRY_SIZE32 * 3).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tlsRva + 12, callbackTableRva, true);
  dv.setUint32(callbackTableRva, firstCallbackRva, true);
  dv.setUint32(callbackTableRva + TLS_CALLBACK_ENTRY_SIZE32, secondCallbackRva, true);
  dv.setUint32(callbackTableRva + TLS_CALLBACK_ENTRY_SIZE32 * 2, 0, true);

  const sparseRvaToOff = (rva: number): number | null => {
    if (rva === tlsRva || rva === callbackTableRva) return rva;
    return null;
  };

  const tls = expectDefined(await parseTlsDirectory32(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY32_SIZE }],
    sparseRvaToOff,
    0n
  ));

  assert.deepEqual(tls.CallbackRvas, [firstCallbackRva]);
  assert.ok(tls.warnings?.some(warning => /truncated or unmapped before the null terminator/i.test(warning)));
});

void test("parseTlsDirectory walks the full null-terminated callback array without a hard 1024-entry cap", async () => {
  const tlsRva = IMAGE_TLS_DIRECTORY32_SIZE;
  const callbackTableRva = tlsRva + IMAGE_TLS_DIRECTORY32_SIZE;
  const callbackCount = 1025; // Deliberately 1024 + 1 to prove the parser follows the null terminator instead of a cap.
  const firstCallbackRva = 0x2000;
  const bytes = new Uint8Array(
    callbackTableRva + (callbackCount + 1) * TLS_CALLBACK_ENTRY_SIZE32
  ).fill(0);
  const dv = new DataView(bytes.buffer);

  // Microsoft PE format, TLS Callback Functions:
  // the callback array is null-terminated; the format does not define a fixed maximum entry count.
  dv.setUint32(tlsRva + 12, callbackTableRva, true);
  for (let index = 0; index < callbackCount; index += 1) {
    dv.setUint32(
      callbackTableRva + index * TLS_CALLBACK_ENTRY_SIZE32,
      firstCallbackRva + index * TLS_CALLBACK_ENTRY_SIZE32,
      true
    );
  }
  dv.setUint32(callbackTableRva + callbackCount * TLS_CALLBACK_ENTRY_SIZE32, 0, true);

  const tls = expectDefined(await parseTlsDirectory32(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY32_SIZE }],
    value => value,
    0n
  ));

  assert.equal(tls.CallbackCount, callbackCount);
  assert.equal(
    tls.CallbackRvas?.at(-1),
    firstCallbackRva + (callbackCount - 1) * TLS_CALLBACK_ENTRY_SIZE32
  );
});

void test("parseTlsDirectory counts callbacks through the null terminator", async () => {
  const tlsRva = IMAGE_TLS_DIRECTORY32_SIZE;
  const callbackTableRva = tlsRva + IMAGE_TLS_DIRECTORY32_SIZE;
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tlsRva + 12, callbackTableRva, true);
  dv.setUint32(callbackTableRva, 0x2000, true);
  dv.setUint32(callbackTableRva + TLS_CALLBACK_ENTRY_SIZE32, 0, true);

  const tls = expectDefined(await parseTlsDirectory32(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY32_SIZE }],
    value => value,
    0n
  ));

  assert.equal(tls.CallbackCount, 1);
  assert.deepEqual(tls.CallbackRvas, [0x2000]);
});
