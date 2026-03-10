"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseTlsDirectory } from "../../analyzers/pe/tls.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

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
  dv.setUint32(0x40, 0x1111, true);
  dv.setUint32(0x44, 0);

  const tls = expectDefined(await parseTlsDirectory(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    value => value,
    () => {},
    false,
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

  const tls64 = expectDefined(await parseTlsDirectory(
    new MockFile(bytes64),
    [{ name: "TLS", rva: 0x10, size: 0x30 }],
    value => (value === 0x10 ? 0 : value),
    () => {},
    true,
    0
  ));
  assert.equal(tls64.CallbackCount, 1);
  assert.deepEqual(tls64.CallbackRvas, [0x7000]);
});

void test("parseTlsDirectory returns null for missing or unmapped TLS directory", async () => {
  const file = new MockFile(new Uint8Array(16));
  assert.equal(await parseTlsDirectory(file, [], value => value, () => {}, false, 0), null);
  assert.equal(await parseTlsDirectory(
    file,
    [{ name: "TLS", rva: 0x20, size: 0x18 }],
    () => null,
    () => {},
    false,
    0
  ), null);
});

void test("parseTlsDirectory returns null for truncated TLS directory headers", async () => {
  const tlsRva = 0x20;
  const truncated32 = new Uint8Array(tlsRva + 0x10).fill(0);
  assert.equal(await parseTlsDirectory(
    new MockFile(truncated32),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    value => value,
    () => {},
    false,
    0
  ), null);

  const truncated64 = new Uint8Array(tlsRva + 0x20).fill(0);
  assert.equal(await parseTlsDirectory(
    new MockFile(truncated64),
    [{ name: "TLS", rva: tlsRva, size: 0x30 }],
    value => value,
    () => {},
    true,
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

  const tls = expectDefined(await parseTlsDirectory(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    value => value,
    () => {},
    false,
    0x2000
  ));
  assert.equal(tls.CallbackCount, 0);
  assert.deepEqual(tls.CallbackRvas, []);

  const bytesOutOfRange = new Uint8Array(64).fill(0);
  const dvOutOfRange = new DataView(bytesOutOfRange.buffer);
  dvOutOfRange.setUint32(tlsRva + 12, 0x1000, true);
  const rvaToOff = (rva: number): number => (rva === tlsRva ? tlsRva : bytesOutOfRange.length + 4);
  const tlsOutOfRange = expectDefined(await parseTlsDirectory(
    new MockFile(bytesOutOfRange),
    [{ name: "TLS", rva: tlsRva, size: 0x18 }],
    rvaToOff,
    () => {},
    false,
    0
  ));
  assert.equal(tlsOutOfRange.CallbackCount, 0);
  assert.deepEqual(tlsOutOfRange.CallbackRvas, []);
});
