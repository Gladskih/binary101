import assert from "node:assert/strict";
import { test } from "node:test";
import { contiguousRvaOffset, isRvaRange, mappedRvaSize, mappedRvaSpan }
  from "../../../../analyzers/pe/rva-mapping.js";

void test("RVA range validation keeps the exclusive DWORD boundary without wrapping", () => {
  // PE format: RVAs are DWORDs, so 2^32 is an exclusive endpoint, never an address.
  assert.equal(isRvaRange(0xffffffff, 1), true);
  assert.equal(isRvaRange(0xffffffff, 2), false);
  assert.equal(isRvaRange(0x100000000, 1), false);
  assert.equal(isRvaRange(-1, 1), false);
  assert.equal(isRvaRange(0, 0), false);
  assert.equal(isRvaRange(NaN, 1), false);
  assert.equal(isRvaRange(0, 1.5), false);
  assert.equal(isRvaRange(0, Infinity), false);
});

void test("mapped ranges stop at gaps, EOF and invalid input", () => {
  const map = (rva: number): number | null => rva < 2 ? rva : null;
  assert.equal(mappedRvaSize(map, 0, 4, 4), 2);
  assert.equal(mappedRvaSize(rva => rva, 0, 4, 1), 1);
  assert.equal(mappedRvaSize(rva => rva, -1, 4, 4), 0);
  assert.equal(mappedRvaSize(rva => rva, 0, 1.5, 4), 0);
  assert.equal(mappedRvaSpan(() => -1, 0, 1, 4), null);
  assert.equal(mappedRvaSpan(() => NaN, 0, 1, 4), null);
  assert.equal(mappedRvaSpan(() => 4, 0, 1, 4), null);
});

void test("range readers distinguish mapped bytes from one physical range", () => {
  const split = (rva: number): number => rva < 2 ? rva : rva + 2;
  assert.equal(mappedRvaSize(split, 0, 4, 8), 4);
  assert.equal(contiguousRvaOffset(split, 0, 4, 8), null);
  assert.equal(contiguousRvaOffset(rva => rva, 0, 4, 4), 0);
  assert.equal(contiguousRvaOffset(() => null, 0, 1, 4), null);
  assert.equal(contiguousRvaOffset(rva => rva, 0, 0, 4), null);
});

void test("span-aware mappings avoid per-byte point lookups and join physical neighbors", () => {
  let calls = 0;
  const mapping = Object.assign(() => { calls += 1; return null; }, {
    span: (rva: number) => ({ offset: rva, size: rva < 2 ? 2 - rva : 4 - rva })
  });
  assert.equal(contiguousRvaOffset(mapping, 0, 4, 4), 0);
  assert.equal(mappedRvaSize(mapping, 0, 4, 4), 4);
  assert.equal(calls, 0);
});

void test("malformed span providers cannot produce empty or unsafe mapping steps", () => {
  const empty = Object.assign(() => 0, { span: () => ({ offset: 0, size: 0 }) });
  const unsafe = Object.assign(() => 0, { span: () => ({ offset: 0, size: NaN }) });
  assert.equal(mappedRvaSpan(empty, 0, 4, 4), null);
  assert.equal(mappedRvaSpan(unsafe, 0, 4, 4), null);
  assert.equal(mappedRvaSpan(rva => rva, 0, 4, NaN), null);
});

void test("spans clamp to the file, requested size and exclusive RVA endpoint", () => {
  const mapping = Object.assign(() => 2, { span: () => ({ offset: 2, size: 8 }) });
  assert.deepEqual(mappedRvaSpan(mapping, 0, 8, 4), { offset: 2, size: 2 });
  assert.deepEqual(mappedRvaSpan(mapping, 0, 1, 16), { offset: 2, size: 1 });
  assert.deepEqual(mappedRvaSpan(mapping, 0xffffffff, 8, 16), { offset: 2, size: 1 });
  assert.equal(mappedRvaSpan(mapping, 0, 0, 16), null);
  assert.equal(mappedRvaSpan(mapping, 0, -1, 16), null);
  assert.equal(mappedRvaSpan(mapping, -1, 1, 16), null);
  assert.equal(mappedRvaSpan(mapping, 0x100000000, 1, 16), null);
  assert.equal(mappedRvaSpan(mapping, 0, 1, 0), null);
});
