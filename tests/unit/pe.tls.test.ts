"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseTlsDirectory32, parseTlsDirectory64 } from "../../analyzers/pe/tls.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const IMAGE_TLS_DIRECTORY32_SIZE = 0x18; // IMAGE_TLS_DIRECTORY32
const IMAGE_TLS_DIRECTORY64_SIZE = 0x30; // IMAGE_TLS_DIRECTORY64
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
    () => {},
    0
  ));
  assert.equal(tls.CallbackCount, 1);
  assert.deepEqual(tls.CallbackRvas, [0x1111]);

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
    () => {},
    0
  ));
  assert.equal(tls64.CallbackCount, 1);
  assert.deepEqual(tls64.CallbackRvas, [0x7000]);
});

void test("parseTlsDirectory returns null for missing or unmapped TLS directory", async () => {
  const file = new MockFile(new Uint8Array(16));
  assert.equal(await parseTlsDirectory32(file, [], value => value, () => {}, 0), null);
  assert.equal(await parseTlsDirectory32(
    file,
    [{ name: "TLS", rva: 0x20, size: 0x18 }],
    () => null,
    () => {},
    0
  ), null);
});

void test("parseTlsDirectory returns null for truncated TLS directory headers", async () => {
  const tlsRva = 0x20;
  const truncated32 = new Uint8Array(tlsRva + 0x10).fill(0);
  assert.equal(await parseTlsDirectory32(
    new MockFile(truncated32),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY32_SIZE }],
    value => value,
    () => {},
    0
  ), null);

  const truncated64 = new Uint8Array(tlsRva + 0x20).fill(0);
  assert.equal(await parseTlsDirectory64(
    new MockFile(truncated64),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY64_SIZE }],
    value => value,
    () => {},
    0
  ), null);
});

void test("parseTlsDirectory respects the declared data-directory size", async () => {
  const tlsRva = IMAGE_TLS_DIRECTORY32_SIZE;
  const bytes32 = new Uint8Array(tlsRva + IMAGE_TLS_DIRECTORY32_SIZE).fill(0);
  const dv32 = new DataView(bytes32.buffer);
  // IMAGE_TLS_DIRECTORY32 is 0x18 bytes, so any smaller declared directory cannot describe a valid header.
  dv32.setUint32(tlsRva + 12, 0x40, true);
  assert.equal(await parseTlsDirectory32(
    new MockFile(bytes32),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY32_SIZE - 1 }],
    value => value,
    () => {},
    0
  ), null);

  const bytes64 = new Uint8Array(tlsRva + IMAGE_TLS_DIRECTORY64_SIZE).fill(0);
  const dv64 = new DataView(bytes64.buffer);
  // IMAGE_TLS_DIRECTORY64 is 0x30 bytes, so any smaller declared directory cannot describe a valid header.
  dv64.setBigUint64(tlsRva + 24, 0x80n, true);
  assert.equal(await parseTlsDirectory64(
    new MockFile(bytes64),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY64_SIZE - 1 }],
    value => value,
    () => {},
    0
  ), null);
});

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
    () => {},
    0x2000
  ));
  assert.equal(tls.CallbackCount, 0);
  assert.deepEqual(tls.CallbackRvas, []);

  const bytesOutOfRange = new Uint8Array(64).fill(0);
  const dvOutOfRange = new DataView(bytesOutOfRange.buffer);
  dvOutOfRange.setUint32(tlsRva + 12, 0x1000, true);
  const rvaToOff = (rva: number): number => (rva === tlsRva ? tlsRva : bytesOutOfRange.length + 4);
  const tlsOutOfRange = expectDefined(await parseTlsDirectory32(
    new MockFile(bytesOutOfRange),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    rvaToOff,
    () => {},
    0
  ));
  assert.equal(tlsOutOfRange.CallbackCount, 0);
  assert.deepEqual(tlsOutOfRange.CallbackRvas, []);
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
    () => {},
    0
  ));

  assert.deepEqual(tls.CallbackRvas, [firstCallbackRva]);
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
    () => {},
    0
  ));

  assert.equal(tls.CallbackCount, callbackCount);
  assert.equal(
    tls.CallbackRvas?.at(-1),
    firstCallbackRva + (callbackCount - 1) * TLS_CALLBACK_ENTRY_SIZE32
  );
});

void test("parseTlsDirectory reports TLS callback coverage only through the null terminator", async () => {
  const tlsRva = IMAGE_TLS_DIRECTORY32_SIZE;
  const callbackTableRva = tlsRva + IMAGE_TLS_DIRECTORY32_SIZE;
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  const coverage: Array<{ label: string; start: number; size: number }> = [];
  dv.setUint32(tlsRva + 12, callbackTableRva, true);
  dv.setUint32(callbackTableRva, 0x2000, true);
  dv.setUint32(callbackTableRva + TLS_CALLBACK_ENTRY_SIZE32, 0, true);

  const tls = expectDefined(await parseTlsDirectory32(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY32_SIZE }],
    value => value,
    (label, start, size) => coverage.push({ label, start, size }),
    0
  ));

  assert.equal(tls.CallbackCount, 1);
  const callbackCoverage = expectDefined(coverage.find(entry => entry.label === "TLS callbacks"));
  assert.deepEqual(callbackCoverage, {
    label: "TLS callbacks",
    start: callbackTableRva,
    size: TLS_CALLBACK_ENTRY_SIZE32 * 2
  });
});
