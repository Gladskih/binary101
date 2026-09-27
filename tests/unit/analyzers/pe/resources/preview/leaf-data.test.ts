"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createGroupLeafLoader,
  readResourceLeafBytes
} from "../../../../../../analyzers/pe/resources/preview/leaf-data.js";
import type {
  ResourceLeafIndex,
  ResourceLeafRecord
} from "../../../../../../analyzers/pe/resources/preview/leaf-index.js";
import type { ResourceLangWithPreview } from "../../../../../../analyzers/pe/resources/preview/types.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

const createLangEntry = (
  dataFileOffset: number | null,
  size: number
): ResourceLangWithPreview => ({
  lang: 1033,
  size,
  codePage: 0,
  dataRVA: 0x2000,
  dataFileOffset,
  reserved: 0
});

const createLeafIndex = (record: ResourceLeafRecord): ResourceLeafIndex =>
  new Map([[7, [record]]]);

void test("readResourceLeafBytes reads payloads from the parsed file offset", async () => {
  const bytes = new Uint8Array([0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd]);

  const loaded = await readResourceLeafBytes(new MockFile(bytes), createLangEntry(4, 3));

  assert.deepStrictEqual([...expectDefined(loaded.data)], [0xaa, 0xbb, 0xcc]);
  assert.equal(loaded.issues, undefined);
});

void test("readResourceLeafBytes reads the complete declared resource", async () => {
  const file = new MockFile(new Uint8Array([1, 2, 3, 4]));
  const loaded = await readResourceLeafBytes(file, createLangEntry(0, 4));
  assert.deepEqual([...expectDefined(loaded.data)], [1, 2, 3, 4]);
  assert.equal(loaded.issues, undefined);
});

void test("readResourceLeafBytes accepts the empty declared range", async () => {
  assert.deepEqual(await readResourceLeafBytes(new MockFile(new Uint8Array(2)), createLangEntry(0, 0)),
    { data: null });
});

for (const size of [-1, Number.NaN, Number.POSITIVE_INFINITY, 1.5]) {
  void test(`readResourceLeafBytes rejects an invalid resource size ${size}`, async () => {
    const loaded = await readResourceLeafBytes(
      new MockFile(new Uint8Array([1, 2])), createLangEntry(0, size));
    assert.equal(loaded.data, null);
    assert.match(loaded.issues?.join(" ") ?? "", /invalid.*size/i);
  });
}

void test("readResourceLeafBytes uses the declared size with an RVA payload reader", async () => {
  const file = new MockFile(new Uint8Array([1, 2, 3]));
  const sizes: number[] = [];
  const reader = Object.assign(file, { readResourceBytes: (_rva: number, size: number) => {
    sizes.push(size);
    return file.readBytes(0, size);
  } });
  const loaded = await readResourceLeafBytes(reader, createLangEntry(0, 3));
  assert.deepEqual(sizes, [3]);
  assert.deepEqual([...expectDefined(loaded.data)], [1, 2, 3]);
});

void test("readResourceLeafBytes accepts payloads at file offset zero", async () => {
  const loaded = await readResourceLeafBytes(
    new MockFile(new Uint8Array([0xaa, 0xbb, 0xcc])),
    createLangEntry(0, 2)
  );

  assert.deepStrictEqual([...expectDefined(loaded.data)], [0xaa, 0xbb]);
  assert.equal(loaded.issues, undefined);
});

void test("readResourceLeafBytes reports unmapped payload offsets without reading", async () => {
  const loaded = await readResourceLeafBytes(
    new MockFile(new Uint8Array(8)),
    createLangEntry(null, 3)
  );

  assert.equal(loaded.data, null);
  assert.match((loaded.issues || []).join(" "), /could not be mapped/i);
});

void test("readResourceLeafBytes rejects negative payload offsets without reading", async () => {
  const loaded = await readResourceLeafBytes(
    new MockFile(new Uint8Array([0xaa, 0xbb])),
    createLangEntry(-1, 1)
  );

  assert.equal(loaded.data, null);
  assert.deepStrictEqual(loaded.issues, ["Resource RVA could not be mapped to a file offset."]);
});

void test("readResourceLeafBytes reports truncated payload reads", async () => {
  const loaded = await readResourceLeafBytes(
    new MockFile(new Uint8Array([0, 0, 0, 0, 0xaa, 0xbb])),
    createLangEntry(4, 4)
  );

  assert.deepStrictEqual([...expectDefined(loaded.data)], [0xaa, 0xbb]);
  assert.match((loaded.issues || []).join(" "), /fewer bytes|declared data size/i);
});

void test("createGroupLeafLoader loads referenced group leaves from parsed file offsets", async () => {
  const index = createLeafIndex({ lang: 1033, dataFileOffset: 2, size: 3 });
  const loadLeaf = createGroupLeafLoader(new MockFile(new Uint8Array([0, 0, 1, 2, 3])), index, "GROUP_ICON", "ICON");

  const loaded = await loadLeaf(7, 1033);

  assert.deepStrictEqual([...expectDefined(loaded.data)], [1, 2, 3]);
  assert.equal(loaded.issues, undefined);
});

void test("createGroupLeafLoader accepts referenced leaves at file offset zero", async () => {
  const index = createLeafIndex({ lang: 1033, dataFileOffset: 0, size: 2 });
  const loadLeaf = createGroupLeafLoader(new MockFile(new Uint8Array([1, 2, 3])), index, "GROUP_ICON", "ICON");

  const loaded = await loadLeaf(7, 1033);

  assert.deepStrictEqual([...expectDefined(loaded.data)], [1, 2]);
  assert.equal(loaded.issues, undefined);
});

void test("createGroupLeafLoader returns null data when the referenced record is absent", async () => {
  const loadLeaf = createGroupLeafLoader(
    new MockFile(new Uint8Array(8)),
    new Map(),
    "GROUP_ICON",
    "ICON"
  );

  assert.deepStrictEqual(await loadLeaf(7, 1033), { data: null });
});

void test("createGroupLeafLoader reports referenced leaves without a file offset", async () => {
  const index = createLeafIndex({ lang: null, dataFileOffset: null, size: 3 });
  const loadLeaf = createGroupLeafLoader(new MockFile(new Uint8Array(8)), index, "GROUP_CURSOR", "CURSOR");

  const loaded = await loadLeaf(7, null);

  assert.equal(loaded.data, null);
  assert.match((loaded.issues || []).join(" "), /GROUP_CURSOR references CURSOR leaf ID 7/i);
});

void test("createGroupLeafLoader rejects referenced leaves with negative file offsets", async () => {
  const index = createLeafIndex({ lang: null, dataFileOffset: -1, size: 3 });
  const loadLeaf = createGroupLeafLoader(new MockFile(new Uint8Array(8)), index, "GROUP_CURSOR", "CURSOR");

  const loaded = await loadLeaf(7, null);

  assert.equal(loaded.data, null);
  assert.deepStrictEqual(loaded.issues, [
    "GROUP_CURSOR references CURSOR leaf ID 7, but its RVA could not be mapped to a file offset."
  ]);
});

void test("createGroupLeafLoader reports zero-sized and truncated referenced leaves", async () => {
  const zeroIndex = createLeafIndex({ lang: null, dataFileOffset: 4, size: 0 });
  const truncatedIndex = createLeafIndex({ lang: null, dataFileOffset: 4, size: 4 });
  const zero = await createGroupLeafLoader(
    new MockFile(new Uint8Array(8)),
    zeroIndex,
    "GROUP_ICON",
    "ICON"
  )(7, null);
  const truncated = await createGroupLeafLoader(
    new MockFile(new Uint8Array([0, 0, 0, 0, 0xaa])),
    truncatedIndex,
    "GROUP_ICON",
    "ICON"
  )(7, null);

  assert.equal(zero.data, null);
  assert.match((zero.issues || []).join(" "), /payload size is zero/i);
  assert.deepStrictEqual([...expectDefined(truncated.data)], [0xaa]);
  assert.match((truncated.issues || []).join(" "), /payload is truncated/i);
});
