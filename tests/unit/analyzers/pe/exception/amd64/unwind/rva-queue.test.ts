"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createCachedRvaOffsetReader,
  createRvaFileOffsetComparer,
  insertPendingUnwindRva
} from "../../../../../../../analyzers/pe/exception/amd64/unwind-rva-queue.js";
import { createRvaAllocator } from "../../../../../../helpers/pe-amd64-unwind-fixture.js";
import type { RvaToOffset } from "../../../../../../../analyzers/pe/types.js";

const spanMapper = () => {
  const span = (rva: number) => rva >= 0x1000 && rva < 0x1010
    ? { offset: 8 + rva - 0x1000, size: 0x1010 - rva } : null;
  return Object.assign((rva: number) => span(rva)?.offset ?? null, { span });
};

void test("offset sorting reuses a proven span rather than caching each address", context => {
  const mapper = spanMapper();
  const span = context.mock.method(mapper, "span");
  const getOffset = createCachedRvaOffsetReader(mapper, 32);

  assert.equal(getOffset(0x1000), 8);
  assert.equal(getOffset(0x100f), 23);
  assert.equal(getOffset(0x1008), 16);
  assert.equal(span.mock.callCount(), 1);
  assert.equal(getOffset(0x1010), null);
  assert.equal(getOffset(0x1000), 8);
  assert.equal(span.mock.callCount(), 2);
});

void test("span offsets refill backwards and clip physical file boundaries", () => {
  const getOffset = createCachedRvaOffsetReader(spanMapper(), 20);

  assert.equal(getOffset(0x1008), 16);
  assert.equal(getOffset(0x1000), 8);
  assert.equal(getOffset(0x100b), 19);
  assert.equal(getOffset(0x100c), null);
});

void test("span sorting keeps discontiguous sections separate", () => {
  const mapper: RvaToOffset = Object.assign(spanMapper(), {
    span: (rva: number) => rva < 0x1002
      ? { offset: rva - 0x1000, size: 0x1002 - rva }
      : { offset: 10 + rva - 0x1002, size: 0x1004 - rva }
  });
  const getOffset = createCachedRvaOffsetReader(mapper, 16);

  assert.equal(getOffset(0x1000), 0);
  assert.equal(getOffset(0x1001), 1);
  assert.equal(getOffset(0x1002), 10);
  assert.equal(getOffset(0x1003), 11);
});

for (const rva of [-1, NaN, Infinity, 0x1000 + 0.5, 0x1_0000_0000]) {
  void test(`span offset cache rejects invalid RVA ${rva} after a cache hit`, () => {
    const getOffset = createCachedRvaOffsetReader(spanMapper(), 32);

    assert.equal(getOffset(0x1000), 8);
    assert.equal(getOffset(rva), null);
  });
}

for (const span of [{ offset: 0, size: 0 }, { offset: 0, size: -1 },
  { offset: 0, size: 0.5 }, { offset: 0, size: Infinity }, { offset: 0, size: NaN },
  { offset: -1, size: 4 }, { offset: 0.5, size: 4 }, { offset: NaN, size: 4 },
  { offset: Infinity, size: 4 }, { offset: 32, size: 4 }]) {
  void test(`span offset cache rejects invalid span ${JSON.stringify(span)}`, () => {
    const mapper: RvaToOffset = Object.assign(spanMapper(), { span: () => span });

    assert.equal(createCachedRvaOffsetReader(mapper, 32)(0x1000), null);
  });
}

void test("span offset cache clips the last representable RVA", () => {
  const mapper: RvaToOffset = Object.assign(spanMapper(), {
    span: () => ({ offset: 0, size: 16 })
  });
  const getOffset = createCachedRvaOffsetReader(mapper, 32);

  assert.equal(getOffset(0xffffffff), 0);
  assert.equal(getOffset(0x1_0000_0000), null);
});

void test("point-only mappers retain per-address caching with a file size", context => {
  const mapper = context.mock.fn((rva: number) => rva === 4 ? 8 : null);
  const getOffset = createCachedRvaOffsetReader(mapper, 32);

  assert.equal(getOffset(4), 8);
  assert.equal(getOffset(4), 8);
  assert.equal(getOffset(8), null);
  assert.equal(getOffset(8), null);
  assert.equal(mapper.mock.callCount(), 2);
});

void test("a span mapper without a file bound retains the point-cache contract", context => {
  const point = context.mock.fn(() => 8);
  const mapper: RvaToOffset = Object.assign(point, { span: spanMapper().span });
  const getOffset = createCachedRvaOffsetReader(mapper);

  assert.equal(getOffset(4), 8);
  assert.equal(getOffset(4), 8);
  assert.equal(point.mock.callCount(), 1);
});

void test("unmapped sort keys follow mapped keys and remain ordered by RVA", () => {
  const compare = createRvaFileOffsetComparer(rva => rva === 4 ? 0 : null);

  assert.equal(Math.sign(compare(8, 4)), 1);
  assert.equal(Math.sign(compare(4, 8)), -1);
  assert.equal(Math.sign(compare(8, 12)), -1);
  assert.equal(Math.sign(compare(12, 8)), 1);
  assert.equal(compare(8, 8), 0);
});

void test("aliased physical sort keys use the RVA as a stable tiebreaker", () => {
  const compare = createRvaFileOffsetComparer(() => 0);

  assert.equal(Math.sign(compare(4, 8)), -1);
  assert.equal(Math.sign(compare(8, 4)), 1);
  assert.equal(compare(4, 4), 0);
});

void test("an unmapped lower RVA still sorts after a mapped higher RVA", () => {
  const compare = createRvaFileOffsetComparer(rva => rva === 12 ? 0 : null);

  assert.equal(Math.sign(compare(4, 12)), 1);
  assert.equal(Math.sign(compare(12, 4)), -1);
});

void test("pending insertion handles front, middle, equal, and empty intervals", () => {
  const pending = [4, 12, 20];
  const empty: number[] = [];

  insertPendingUnwindRva(pending, 1, 8, (left, right) => left - right);
  insertPendingUnwindRva(pending, 1, 16, (left, right) => left - right);
  insertPendingUnwindRva(pending, 1, 16, (left, right) => left - right);
  insertPendingUnwindRva(empty, 0, 4, (left, right) => left - right);

  assert.deepEqual(pending, [4, 8, 12, 16, 16, 20]);
  assert.deepEqual(empty, [4]);
});

void test("createCachedRvaOffsetReader caches mapped and unmapped RVAs", () => {
  const allocator = createRvaAllocator();
  const mappedRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const unmappedRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const observedRvas: number[] = [];
  const getOffset = createCachedRvaOffsetReader(rva => {
    observedRvas.push(rva);
    return rva === mappedRva ? Uint8Array.BYTES_PER_ELEMENT : null;
  });
  assert.strictEqual(getOffset(mappedRva), Uint8Array.BYTES_PER_ELEMENT);
  assert.strictEqual(getOffset(mappedRva), Uint8Array.BYTES_PER_ELEMENT);
  assert.strictEqual(getOffset(unmappedRva), null);
  assert.strictEqual(getOffset(unmappedRva), null);
  assert.deepEqual(observedRvas, [mappedRva, unmappedRva]);
});

void test("createRvaFileOffsetComparer orders by mapped file offset before RVA", () => {
  const allocator = createRvaAllocator();
  const secondFileOffsetRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const tieBreakerRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const firstFileOffsetRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const unmappedRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const offsets = new Map([
    [firstFileOffsetRva, Uint8Array.BYTES_PER_ELEMENT],
    [secondFileOffsetRva, Uint16Array.BYTES_PER_ELEMENT * 2],
    [tieBreakerRva, Uint16Array.BYTES_PER_ELEMENT * 2]
  ]);
  const compare = createRvaFileOffsetComparer(rva => offsets.get(rva) ?? null);
  const sorted = [unmappedRva, secondFileOffsetRva, tieBreakerRva, firstFileOffsetRva].sort(
    compare
  );
  assert.deepEqual(sorted, [
    firstFileOffsetRva,
    secondFileOffsetRva,
    tieBreakerRva,
    unmappedRva
  ]);
});

void test("insertPendingUnwindRva keeps the processed queue prefix untouched", () => {
  const allocator = createRvaAllocator();
  const processedRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const insertedRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const nextPendingRva = allocator.allocate(Uint8Array.BYTES_PER_ELEMENT);
  const pendingUnwindRvas = [processedRva, nextPendingRva];
  insertPendingUnwindRva(
    pendingUnwindRvas,
    1,
    insertedRva,
    (left, right) => left - right
  );
  assert.deepEqual(pendingUnwindRvas, [processedRva, insertedRva, nextPendingRva]);
});
