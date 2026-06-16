"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  ResourceDirectoryEntry,
  ResourceDirectoryLabelReadResult
} from "../../../../../../analyzers/pe/resources/directory-rules.js";
import type { ResourceSpanResolver } from "../../../../../../analyzers/pe/resources/relative-offsets.js";
import {
  createResourceLabelReader,
  createResourceLeafPathReader,
  createResourcePathNodeReader
} from "../../../../../../analyzers/pe/resources/tree-readers.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

const createResolver = (
  resolveRelOffset: (rel: number, len: number) => number | null = rel => rel,
  resolveRvaOffset: (rva: number) => number | null = rva => rva
): ResourceSpanResolver => ({
  describeRelOffsetFailure: (rel, len, subject) => `${subject} failed at ${rel}:${len}`,
  formatRelOffset: rel => `0x${rel.toString(16)}`,
  resolveRvaOffset,
  resolveRelOffset
});

const createLabelReader = (
  bytes: Uint8Array,
  resolveRelOffset: (rel: number, len: number) => number | null = rel => rel
) =>
  createResourceLabelReader(
    new MockFile(bytes),
    { name: "RESOURCE", rva: 0x1000, size: 6 },
    createResolver(resolveRelOffset),
    new TextDecoder("utf-16le")
  );

const labelResult = (text: string): ResourceDirectoryLabelReadResult => ({
  text,
  issues: [],
  resourceStringRanges: []
});

const stringEntry = (nameOrId: number | null, invalidNameOffset = false): ResourceDirectoryEntry => ({
  nameIsString: true,
  nameOrId,
  subdir: false,
  target: 0,
  ...(invalidNameOffset ? { invalidNameOffset } : {})
});

const idEntry = (nameOrId: number | null): ResourceDirectoryEntry => ({
  nameIsString: false,
  nameOrId,
  subdir: false,
  target: 0
});

void test("createResourceLabelReader decodes cached UTF-16 labels and reports truncation", async () => {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setUint16(1, 2, true);
  view.setUint16(3, 0x0041, true);
  const readLabel = createLabelReader(bytes);

  const first = await readLabel(1);
  const second = await readLabel(1);

  assert.strictEqual(first, second);
  assert.equal(first.text, "A");
  assert.deepStrictEqual(first.resourceStringRanges, [{ start: 1, end: 6 }]);
  assert.deepStrictEqual(first.issues, [
    "Resource string name at 0x1 is not word-aligned.",
    "Resource string name at 0x1 is truncated."
  ]);
});

void test("createResourceLabelReader reports unmapped and truncated label headers", async () => {
  const unmapped = await createLabelReader(new Uint8Array(4), () => null)(0);
  const truncated = await createLabelReader(new Uint8Array(1))(0);

  assert.equal(unmapped.text, "");
  assert.deepStrictEqual(unmapped.issues, [
    "Resource string name header at 0x0 failed at 0:2"
  ]);
  assert.deepStrictEqual(unmapped.resourceStringRanges, []);
  assert.equal(truncated.text, "");
  assert.deepStrictEqual(truncated.issues, [
    "Resource string name header at 0x0 is truncated."
  ]);
  assert.deepStrictEqual(truncated.resourceStringRanges, []);
});

void test("createResourceLabelReader reports unmapped string payloads", async () => {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint16(0, 1, true);
  const readLabel = createLabelReader(
    bytes,
    (rel, len) => (rel === 2 && len === 2 ? null : rel)
  );

  const result = await readLabel(0);

  assert.equal(result.text, "");
  assert.deepStrictEqual(result.issues, [
    "Resource string name payload at 0x2 failed at 2:2"
  ]);
  assert.deepStrictEqual(result.resourceStringRanges, [{ start: 0, end: 4 }]);
});

void test("path node reader returns nodes, labels, and label issues", async () => {
  const readPathNode = createResourcePathNodeReader(async rel => ({
    ...labelResult(`name-${rel}`),
    issues: [`issue-${rel}`],
    resourceStringRanges: [{ start: rel, end: rel + 2 }]
  }));

  assert.deepStrictEqual(await readPathNode(stringEntry(7)), {
    node: { id: null, name: "name-7" },
    issues: ["issue-7"],
    resourceStringRanges: [{ start: 7, end: 9 }]
  });
  assert.deepStrictEqual(await readPathNode(stringEntry(7, true)), {
    node: { id: null, name: null },
    issues: [],
    resourceStringRanges: []
  });
  assert.deepStrictEqual(await readPathNode(idEntry(3)), {
    node: { id: 3, name: null },
    issues: [],
    resourceStringRanges: []
  });
  assert.deepStrictEqual(await readPathNode(idEntry(null)), {
    node: { id: null, name: null },
    issues: [],
    resourceStringRanges: []
  });
});

void test("createResourceLeafPathReader reads data entries and records layout metadata", async () => {
  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x2000, true);
  view.setUint32(4, 4, true);
  view.setUint32(8, 1252, true);
  view.setUint32(12, 1, true);
  const readLeaf = createResourceLeafPathReader(
    (offset, length) => new MockFile(bytes).read(offset, length),
    createResolver(rel => rel, () => 0x40)
  );

  const result = await readLeaf(0, [{ id: 3, name: null }]);

  assert.deepStrictEqual(result.leaf, {
    nodes: [{ id: 3, name: null }],
    dataRVA: 0x2000,
    dataFileOffset: 0x40,
    size: 4,
    codePage: 1252,
    reserved: 1
  });
  assert.deepStrictEqual(result.resourceDataEntry, {
    start: 0,
    end: 16,
    dataRva: 0x2000,
    dataFileOffset: 0x40,
    size: 4
  });
  assert.match(result.issues.join(" "), /Reserved is non-zero/i);
});

void test("createResourceLeafPathReader reports unmapped and truncated data entries", async () => {
  const unmapped = await createResourceLeafPathReader(
    async () => new DataView(new ArrayBuffer(16)),
    createResolver(() => null)
  )(0, []);
  const truncated = await createResourceLeafPathReader(
    async () => new DataView(new ArrayBuffer(4)),
    createResolver()
  )(0, []);

  assert.equal(unmapped.leaf, null);
  assert.equal(unmapped.resourceDataEntry, null);
  assert.match(unmapped.issues.join(" "), /data entry.*failed/i);
  assert.equal(truncated.leaf, null);
  assert.equal(truncated.resourceDataEntry, null);
  assert.match(truncated.issues.join(" "), /data entry.*truncated/i);
});
