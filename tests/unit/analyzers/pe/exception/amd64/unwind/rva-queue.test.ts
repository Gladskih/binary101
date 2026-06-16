"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createCachedRvaOffsetReader,
  createRvaFileOffsetComparer,
  insertPendingUnwindRva
} from "../../../../../../../analyzers/pe/exception/amd64/unwind-rva-queue.js";
import { createRvaAllocator } from "../../../../../../helpers/pe-amd64-unwind-fixture.js";

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
