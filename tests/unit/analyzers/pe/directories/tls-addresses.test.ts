"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  isReadableMappedTlsVa, isTlsImageVa, toTlsRvaFromVa
} from "../../../../../analyzers/pe/directories/tls-addresses.js";
import { createTlsMappingFixture } from "../../../../fixtures/pe-tls-mapping.js";

for (const byteLength of [-1, 0, 0.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
  void test(`TLS image VA rejects invalid byte length ${byteLength}`, () => {
    const { section } = createTlsMappingFixture(4);

    assert.equal(isTlsImageVa(BigInt(section.virtualAddress), byteLength, 0n, [section]), false);
  });
}

for (const virtualSize of [1, 2, 3]) {
  void test(`TLS index cannot fit in a ${virtualSize}-byte section`, () => {
    const { section } = createTlsMappingFixture(4);
    section.virtualSize = virtualSize;

    assert.equal(isTlsImageVa(BigInt(section.virtualAddress), 4, 0n, [section]), false);
  });
}

void test("TLS image VA accepts a full DWORD and rejects a one-byte overrun", () => {
  const { section } = createTlsMappingFixture(4);

  assert.equal(isTlsImageVa(BigInt(section.virtualAddress), 4, 0n, [section]), true);
  assert.equal(isTlsImageVa(BigInt(section.virtualAddress + 1), 4, 0n, [section]), false);
  assert.equal(isTlsImageVa(BigInt(section.virtualAddress - 1), 4, 0n, [section]), false);
  assert.equal(isTlsImageVa(BigInt(section.virtualAddress + 4), 4, 0n, [section]), false);
});

void test("TLS image VA uses raw size when VirtualSize is zero", () => {
  const { section } = createTlsMappingFixture(4);
  section.virtualSize = 0;

  assert.equal(isTlsImageVa(BigInt(section.virtualAddress), 4, 0n, [section]), true);
});

void test("TLS image VA permits virtual zero-fill storage", () => {
  const { section } = createTlsMappingFixture(4);
  section.sizeOfRawData = 0;

  assert.equal(isTlsImageVa(BigInt(section.virtualAddress), 4, 0n, [section]), true);
});

void test("TLS image VA validates the entire DWORD against the RVA limit", () => {
  const { section } = createTlsMappingFixture(4);
  // Malformed section extends beyond the DWORD RVA address space.
  section.virtualAddress = 0xfffffffc;
  section.virtualSize = 8;

  assert.equal(isTlsImageVa(0xfffffffcn, 4, 0n, [section]), true);
  assert.equal(isTlsImageVa(0xfffffffdn, 4, 0n, [section]), false);
});

void test("TLS image VA selects the second of adjacent sections at their boundary", () => {
  const { section } = createTlsMappingFixture(4);
  const next = { ...section, virtualAddress: section.virtualAddress + section.virtualSize };

  assert.equal(isTlsImageVa(BigInt(next.virtualAddress), 4, 0n, [section, next]), true);
});

void test("TLS VA conversion distinguishes null from a nonzero VA at the image base", () => {
  assert.equal(toTlsRvaFromVa(0n, 0n), null);
  assert.equal(toTlsRvaFromVa(1n, 1n), 0);
  assert.equal(toTlsRvaFromVa(1n, 2n), null);
  assert.equal(toTlsRvaFromVa(0xffffffffn, 0n), 0xffffffff);
  assert.equal(toTlsRvaFromVa(0x100000000n, 0n), null);
});

for (const [offset, expected] of [[null, false], [-1, false], [0, true], [1, false]] as const) {
  void test(`TLS mapped VA checks offset ${offset} against file boundaries`, () => {
    assert.equal(isReadableMappedTlsVa(1n, 4, 0n, rva => offset == null ? null : offset + rva - 1, 4), expected);
  });
}

void test("TLS mapped VA rejects null VAs before mapping", () => {
  assert.equal(isReadableMappedTlsVa(0n, 4, 0n, () => 0, 4), false);
});
