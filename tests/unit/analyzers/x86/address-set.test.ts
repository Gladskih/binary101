import assert from "node:assert/strict";
import { test } from "node:test";
import { createX86RvaSet, createX86VaddrSet } from "../../../../analyzers/x86/address-set.js";

void test("RVA bits preserve adjacent starts, byte boundaries and the last 32-bit page", () => {
  const addresses = createX86RvaSet();

  assert.equal(addresses.has(0), false);
  addresses.delete(0);
  addresses.add(0);
  addresses.add(1);
  addresses.add(7);
  addresses.add(8);
  addresses.add(65535);
  addresses.add(65536);
  addresses.add(0xffffffff);
  addresses.add(7);
  addresses.delete(7);
  addresses.delete(65536);

  assert.equal(addresses.has(0), true);
  assert.equal(addresses.has(1), true);
  assert.equal(addresses.has(6), false);
  assert.equal(addresses.has(7), false);
  assert.equal(addresses.has(8), true);
  assert.equal(addresses.has(65535), true);
  assert.equal(addresses.has(65536), false);
  assert.equal(addresses.has(0xffffffff), true);
  addresses.add(7);
  assert.equal(addresses.has(7), true);
});

for (const invalid of [-1, 0.5, NaN, Infinity, -Infinity, 0x100000000]) {
  void test(`invalid RVA ${invalid} cannot alias or clear a valid address`, () => {
    const addresses = createX86RvaSet();
    addresses.add(0);
    addresses.add(0xffffffff);

    addresses.add(invalid);
    assert.equal(addresses.has(invalid), false);
    addresses.delete(invalid);

    assert.equal(addresses.has(invalid), false);
    assert.equal(addresses.has(0), true);
    assert.equal(addresses.has(0xffffffff), true);
  });
}

void test("virtual address bits remain distinct above the safe integer and 32-bit boundaries", () => {
  const addresses = createX86VaddrSet();

  assert.equal(addresses.has(0n), false);
  addresses.delete(0n);
  addresses.add(0n);
  addresses.add(1n);
  addresses.add(7n);
  addresses.add(8n);
  addresses.add(65535n);
  addresses.add(65536n);
  addresses.add(0x100000001n);
  addresses.add(0xffff800000000001n);
  addresses.add(0xffffffffffffffffn);
  addresses.add(7n);
  addresses.delete(7n);
  addresses.delete(65536n);
  addresses.delete(0xffff800000000001n);

  assert.equal(addresses.has(0n), true);
  assert.equal(addresses.has(1n), true);
  assert.equal(addresses.has(6n), false);
  assert.equal(addresses.has(7n), false);
  assert.equal(addresses.has(8n), true);
  assert.equal(addresses.has(65535n), true);
  assert.equal(addresses.has(65536n), false);
  assert.equal(addresses.has(0x100000001n), true);
  assert.equal(addresses.has(0xffff800000000001n), false);
  assert.equal(addresses.has(0xffffffffffffffffn), true);
  addresses.add(7n);
  assert.equal(addresses.has(7n), true);
});

for (const invalid of [-1n, 0x10000000000000000n]) {
  void test(`invalid virtual address ${invalid} cannot alias or clear valid addresses`, () => {
    const addresses = createX86VaddrSet();
    addresses.add(0n);
    addresses.add(0xffffffffffffffffn);

    addresses.add(invalid);
    assert.equal(addresses.has(invalid), false);
    addresses.delete(invalid);

    assert.equal(addresses.has(invalid), false);
    assert.equal(addresses.has(0n), true);
    assert.equal(addresses.has(0xffffffffffffffffn), true);
  });
}

void test("rejected addresses do not allocate bitmap pages", context => {
  const rvas = createX86RvaSet();
  const vaddrs = createX86VaddrSet();
  const allocation = context.mock.method(globalThis, "Uint8Array");

  rvas.add(-1);
  rvas.add(0.5);
  rvas.add(NaN);
  rvas.add(Infinity);
  rvas.add(0x100000000);
  vaddrs.add(-1n);
  vaddrs.add(0x10000000000000000n);

  assert.equal(allocation.mock.callCount(), 0);
  rvas.add(0);
  vaddrs.add(0n);
  assert.equal(allocation.mock.callCount(), 2);
});
