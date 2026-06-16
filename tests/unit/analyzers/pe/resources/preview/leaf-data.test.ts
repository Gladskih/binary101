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
