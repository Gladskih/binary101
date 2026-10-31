import assert from "node:assert/strict";
import { test } from "node:test";
import { readRccTree } from "../../../../analyzers/embedded-resources/rcc-tree.js";
import { minimalRcc, embeddedResourceFixture } from "../../../fixtures/embedded-resource-builders.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("decodes every node field with exact big-endian widths and absolute content bounds", async () => {
  const fixture = minimalRcc(2);
  const view = new DataView(fixture.bytes.buffer);
  view.setBigUint64(fixture.tree + 14, 0x0102030405060708n);
  view.setBigUint64(fixture.tree + fixture.nodeSize + 14, 0x1020304050607080n);
  view.setUint16(fixture.tree + fixture.nodeSize + 6, 0x1234);
  view.setUint16(fixture.tree + fixture.nodeSize + 8, 0x5678);
  const nodes = await readRccTree(new MockFile(fixture.bytes), { offset: fixture.tree, size: 44 },
    { offset: fixture.names, size: 8 }, { offset: fixture.data, size: 9 }, 22);
  assert.deepEqual(nodes, [
    { name: "", parent: null, nameOffset: 0, flags: 2, childCount: 1, firstChild: 1,
      timestamp: 0x0102030405060708n },
    { name: "a", parent: 0, nameOffset: 0, flags: 0, nameHash: 97, territory: 0x1234, language: 0x5678,
      dataOffset: 0, timestamp: 0x1020304050607080n,
      payload: { offset: fixture.data + 4, size: 5 } }
  ]);
});

void test("decodes shared locale names and payload headers only once per tree", async () => {
  const bytes = embeddedResourceFixture("oracle-v1.rcc");
  const view = new DataView(bytes.buffer);
  const tree = view.getUint32(8);
  const data = view.getUint32(12);
  const names = view.getUint32(16);
  // Two locales share the same RCC name and content references (Qt rcc deduplication).
  bytes.set(bytes.slice(tree + 3 * 14, tree + 4 * 14), tree + 4 * 14);
  view.setUint16(tree + 4 * 14 + 6, 1);
  const file = new MockFile(bytes);
  const reads = new Map<number, number>();
  const reader = { size: file.size, readBytes: file.readBytes.bind(file),
    read: (offset: number, size: number) => {
      reads.set(offset, (reads.get(offset) ?? 0) + 1);
      return file.read(offset, size);
    } };
  const nodes = await readRccTree(reader, { offset: tree, size: bytes.length - tree },
    { offset: names, size: tree - names }, { offset: data, size: names - data }, 14);
  assert.equal(nodes.length, 5);
  assert.equal(reads.get(names + nodes[3]!.nameOffset), 1);
  assert.equal(reads.get(data + nodes[3]!.dataOffset!), 1);
});

void test("does not read past a complete short Zstandard frame when inspecting its size", async () => {
  // Zstandard single-segment frame with empty content and a final empty raw block.
  const fixture = minimalRcc(3, new Uint8Array([0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 1, 0, 0]));
  new DataView(fixture.bytes.buffer).setUint16(fixture.tree + fixture.nodeSize + 4, 4);
  const nodes = await readRccTree(new MockFile(fixture.bytes), { offset: fixture.tree, size: 44 },
    { offset: fixture.names, size: 8 }, { offset: fixture.data, size: 13 }, 22);
  assert.deepEqual(nodes[1]?.payload,
    { offset: fixture.data + 4, size: 9, uncompressedSize: 0 });
});

void test("reads shifted Qt payloads and root names without confusing table-relative and file-relative offsets", async () => {
  const fixture = minimalRcc();
  const bytes = new Uint8Array(fixture.bytes.length + 7);
  bytes.set(fixture.bytes, 7);
  const nodes = await readRccTree(new MockFile(bytes), { offset: fixture.tree + 7, size: 28 },
    { offset: fixture.names + 7, size: 8 }, { offset: fixture.data + 7, size: 9 }, 14);
  assert.deepEqual(nodes[1]?.payload, { offset: fixture.data + 11, size: 5 });
  assert.equal(nodes[1]?.timestamp, undefined);
});

void test("resolves an uncompressed file at a nonzero offset within the RCC data table", async () => {
  const fixture = minimalRcc();
  const bytes = new Uint8Array(fixture.bytes.length + 4);
  bytes.set(fixture.bytes.subarray(0, fixture.data));
  bytes.set(fixture.bytes.subarray(fixture.data), fixture.data + 4);
  new DataView(bytes.buffer).setUint32(fixture.tree + fixture.nodeSize + 10, 4);
  const nodes = await readRccTree(new MockFile(bytes), { offset: fixture.tree, size: 28 },
    { offset: fixture.names, size: 8 }, { offset: fixture.data, size: 13 }, 14);
  assert.deepEqual(nodes[1]?.payload, { offset: fixture.data + 8, size: 5 });
});

void test("keeps differing compression interpretations separate for a shared data block", async () => {
  const bytes = embeddedResourceFixture("oracle-v1.rcc");
  const view = new DataView(bytes.buffer);
  const tree = view.getUint32(8);
  const data = view.getUint32(12);
  const names = view.getUint32(16);
  bytes.set(bytes.slice(tree + 3 * 14, tree + 4 * 14), tree + 4 * 14);
  view.setUint16(tree + 4 * 14 + 4, 0);
  view.setUint16(tree + 4 * 14 + 6, 1);
  const nodes = await readRccTree(new MockFile(bytes), { offset: tree, size: bytes.length - tree },
    { offset: names, size: tree - names }, { offset: data, size: names - data }, 14);
  assert.equal(nodes[3]?.payload?.uncompressedSize, 1300);
  assert.deepEqual(nodes[4]?.payload,
    { offset: nodes[3]!.payload!.offset - 4, size: nodes[3]!.payload!.size + 4 });
});

void test("bounds the root, name and data tables even when no payload is present", async () => {
  const fixture = minimalRcc();
  const file = new MockFile(fixture.bytes);
  await assert.rejects(readRccTree(file, { offset: fixture.tree, size: 13 },
    { offset: fixture.names, size: 8 }, { offset: fixture.data, size: 9 }, 14), /truncated/);
  await assert.rejects(readRccTree(file, { offset: fixture.tree, size: 28 },
    { offset: fixture.names, size: 7 }, { offset: fixture.data, size: 9 }, 14), /truncated/);
  await assert.rejects(readRccTree(file, { offset: fixture.tree, size: 28 },
    { offset: fixture.names, size: 8 }, { offset: fixture.data, size: 8 }, 14), /payload exceeds/);
});

for (const version of [1, 2, 3]) {
  void test(`preserves generated RCC v${version} stored payload and qCompress prefix bounds`, async () => {
    const bytes = embeddedResourceFixture(`oracle-v${version}.rcc`);
    const view = new DataView(bytes.buffer);
    const tree = view.getUint32(8);
    const data = view.getUint32(12);
    const names = view.getUint32(16);
    const nodes = await readRccTree(new MockFile(bytes), { offset: tree, size: bytes.length - tree },
      { offset: names, size: tree - names }, { offset: data, size: names - data }, version === 1 ? 14 : 22);
    assert.equal(nodes[3]?.payload?.uncompressedSize, 1300);
    assert.equal(nodes[4]?.payload?.size, 28);
    assert.equal(nodes[3]?.flags, version === 3 ? 4 : 1);
    assert.equal(nodes[3]?.payload?.offset, data + nodes[3]!.dataOffset! + (version === 3 ? 4 : 8));
    assert.equal(nodes[3]?.payload?.size, version === 3 ? 44 : 45);
  });
}
