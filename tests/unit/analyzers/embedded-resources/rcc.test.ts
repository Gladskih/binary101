import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeRcc } from "../../../../analyzers/embedded-resources/rcc.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { embeddedResourceFixture, minimalRcc, overwriteResource } from "../../../fixtures/embedded-resource-builders.js";
import { decodeRccArrays } from "../../../../analyzers/embedded-resources/rcc.js";
import { resolveResourcePayload } from "../../../../analyzers/embedded-resources/payload.js";

for (const version of [1, 2, 3]) {
  void test(`decodes generated Qt RCC v${version} hierarchy, names and payloads`, async () => {
    const bytes = embeddedResourceFixture(`oracle-v${version}.rcc`);
    const result = await decodeRcc(new MockFile(bytes), 0, bytes.length);
    assert.deepEqual(result.issues, []);
    assert.ok(result.value);
    assert.equal(result.value.version, version);
    assert.deepEqual(result.value.entries.map(entry => entry.name),
      ["", "org", "binary101", "message.txt", "plain.txt"]);
    assert.deepEqual(result.value.entries.map(entry => entry.parent), [null, 0, 1, 2, 2]);
    assert.equal(result.value.entries[3]?.payload?.uncompressedSize, 1300);
    assert.equal(resolveResourcePayload(result.value.format, result.value.entries[3]!)?.compression,
      version === 3 ? "zstd" : "zlib");
    const arrays = await decodeRccArrays(new MockFile(bytes), result.value.tree, result.value.names, result.value.data);
    assert.deepEqual(arrays.issues, []);
    assert.equal(arrays.value?.version, version === 1 ? 1 : null);
  });
}

void test("decodes valid minimal RCC and preserves locale and timestamp fields", async () => {
  const fixture = minimalRcc(2);
  const bytes = overwriteResource(overwriteResource(fixture.bytes,
    fixture.tree + fixture.nodeSize + 6, 9, "be16"), fixture.tree + fixture.nodeSize + 8, 42, "be16");
  const result = await decodeRcc(new MockFile(bytes), 0, bytes.length);
  assert.deepEqual(result.issues, []);
  assert.equal(result.value?.entries[1]?.territory, 9);
  assert.equal(result.value?.entries[1]?.language, 42);
  assert.equal(result.value?.entries[1]?.timestamp, 0n);
  assert.deepEqual(result.value?.tree, { offset: fixture.tree, size: 44 });
  assert.deepEqual(result.value?.names, { offset: fixture.names, size: 8 });
  assert.deepEqual(result.value?.data, { offset: fixture.data, size: 9 });
});

void test("validates feature flags and version-specific compression", async () => {
  const oracle = embeddedResourceFixture("oracle-v3.rcc");
  const missing = await decodeRcc(new MockFile(overwriteResource(oracle, 20, 0, "be32")), 0, oracle.length);
  assert.match(missing.issues.join(), /absent from feature flags/);
  const unknown = await decodeRcc(new MockFile(overwriteResource(oracle, 20, 2, "be32")), 0, oracle.length);
  assert.match(unknown.issues.join(), /Unsupported RCC feature flags/);
  const old = await decodeRcc(new MockFile(overwriteResource(oracle, 4, 2, "be32")), 0, oracle.length);
  assert.match(old.issues.join(), /Zstandard requires RCC v3/);
});

void test("rejects short qCompress prefixes and unsupported node flag combinations", async () => {
  const fixture = minimalRcc(1, new Uint8Array(3));
  const short = overwriteResource(fixture.bytes, fixture.tree + fixture.nodeSize + 4, 1, "be16");
  assert.match((await decodeRcc(new MockFile(short), 0, short.length)).issues.join(), /qCompress/);
  const combined = overwriteResource(fixture.bytes, fixture.tree + fixture.nodeSize + 4, 5, "be16");
  assert.match((await decodeRcc(new MockFile(combined), 0, combined.length)).issues.join(), /flags/);
});

void test("accepts the exact qCompress prefix boundary and preserves its empty stream range", async () => {
  const fixture = minimalRcc(1, new Uint8Array(4));
  const bytes = overwriteResource(fixture.bytes, fixture.tree + fixture.nodeSize + 4, 1, "be16");
  const result = await decodeRcc(new MockFile(bytes), 0, bytes.length);
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.value?.entries[1]?.payload,
    { offset: fixture.data + 8, size: 0, uncompressedSize: 0 });
});

void test("validates sibling hash ordering, locale uniqueness and tree reachability", async () => {
  const bytes = embeddedResourceFixture("oracle-v1.rcc");
  const tree = new DataView(bytes.buffer).getUint32(8);
  const reversed = new Uint8Array(bytes);
  reversed.set(bytes.subarray(tree + 4 * 14, tree + 5 * 14), tree + 3 * 14);
  reversed.set(bytes.subarray(tree + 3 * 14, tree + 4 * 14), tree + 4 * 14);
  assert.match((await decodeRcc(new MockFile(reversed), 0, reversed.length)).issues.join(), /sorted/);
  const duplicate = new Uint8Array(bytes);
  duplicate.set(bytes.subarray(tree + 3 * 14, tree + 4 * 14), tree + 4 * 14);
  assert.match((await decodeRcc(new MockFile(duplicate), 0, duplicate.length)).issues.join(), /Duplicate/);
  const localized = overwriteResource(duplicate, tree + 4 * 14 + 6, 1, "be16");
  assert.ok((await decodeRcc(new MockFile(localized), 0, localized.length)).value);
  const unreachable = overwriteResource(bytes, tree + 10, 2, "be32");
  assert.match((await decodeRcc(new MockFile(unreachable), 0, unreachable.length)).issues.join(), /unreachable/);
});

void test("rejects ambiguous compiled root-only layouts and accepts an unambiguous empty root", async () => {
  const fixture = minimalRcc(2);
  const bytes = overwriteResource(fixture.bytes, fixture.tree + 6, 0, "be32");
  const file = new MockFile(bytes);
  const arrays = await decodeRccArrays(file, { offset: fixture.tree, size: 22 },
    { offset: fixture.names, size: 8 }, { offset: fixture.data, size: bytes.length - fixture.data });
  assert.equal(arrays.value, null);
  const small = await decodeRccArrays(file, { offset: fixture.tree, size: 14 },
    { offset: fixture.names, size: 8 }, { offset: fixture.data, size: bytes.length - fixture.data });
  assert.equal(small.value?.version, 1);
});

void test("decodes Qt's empty qres package with coincident empty name/data tables", async () => {
  const fixture = minimalRcc(3);
  const bytes = fixture.bytes.slice(0, fixture.tree + fixture.nodeSize);
  const view = new DataView(bytes.buffer);
  view.setUint32(12, fixture.tree);
  view.setUint32(16, fixture.tree);
  view.setUint32(fixture.tree + 6, 0);
  const result = await decodeRcc(new MockFile(bytes), 0, bytes.length);
  assert.deepEqual(result.issues, []);
  assert.equal(result.value?.entries.length, 1);
  assert.deepEqual(result.value?.names, { offset: fixture.tree, size: 0 });
  assert.deepEqual(result.value?.data, { offset: fixture.tree, size: 0 });
});

void test("rejects a tree that references records in a following table", async () => {
  const fixture = minimalRcc();
  const bytes = overwriteResource(fixture.bytes, fixture.tree + 6, 3, "be32");
  const result = await decodeRcc(new MockFile(bytes), 0, bytes.length);
  assert.deepEqual(result.issues, ["RCC child range exceeds tree"]);
});

void test("accepts an empty data table positioned exactly at the end of the qres range", async () => {
  const fixture = minimalRcc();
  const bytes = overwriteResource(overwriteResource(fixture.bytes, fixture.tree + 6, 0, "be32"),
    12, fixture.bytes.length, "be32");
  const result = await decodeRcc(new MockFile(bytes), 0, bytes.length);
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.value?.data, { offset: bytes.length, size: 0 });
});

void test("rejects a 14-byte compiled tree whose file declares Zstandard compression", async () => {
  // Valid empty Zstandard single-segment frame, final empty raw block (Zstandard format).
  const fixture = minimalRcc(1, new Uint8Array([0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 1, 0, 0]));
  const bytes = overwriteResource(fixture.bytes, fixture.tree + fixture.nodeSize + 4, 4, "be16");
  const result = await decodeRccArrays(new MockFile(bytes), { offset: fixture.tree, size: 28 },
    { offset: fixture.names, size: 8 }, { offset: fixture.data, size: bytes.length - fixture.data });
  assert.deepEqual(result, { value: null, issues: ["RCC array layout is invalid or ambiguous"] });
});

for (const [label, offset, value, encoding] of [
  ["signature", 0, 0, "be32"], ["version zero", 4, 0, "be32"],
  ["future version", 4, 4, "be32"], ["header overlap", 8, 19, "be32"],
  ["table outside file", 8, 0xffffffff, "be32"], ["duplicate tables", 12, 20, "be32"],
  ["root kind", 24, 0, "be16"], ["root flags", 24, 3, "be16"],
  ["children overflow", 26, 0xffffffff, "be32"], ["root cycle", 30, 0, "be32"],
  ["child flags", 38, 7, "be16"], ["name pointer", 34, 0xffffffff, "be32"],
  ["name length", 48, 0xffff, "be16"], ["name hash", 50, 0, "be32"],
  ["path separator", 54, 47, "be16"], ["empty name", 48, 0, "be16"],
  ["data pointer", 44, 0xffffffff, "be32"], ["data length", 56, 0xffffffff, "be32"]
] as const) {
  void test(`rejects RCC ${label}`, async () => {
    const bytes = overwriteResource(minimalRcc().bytes, offset, value, encoding);
    const result = await decodeRcc(new MockFile(bytes), 0, bytes.length);
    assert.equal(result.value, null);
    assert.equal(result.issues.length, 1);
    assert.equal(result.issues[0], {
      signature: "Invalid qres signature", "version zero": "Unsupported RCC version",
      "future version": "Unsupported RCC version", "header overlap": "Invalid RCC table offsets",
      "table outside file": "Invalid RCC table offsets", "duplicate tables": "Invalid RCC table offsets",
      "root kind": "RCC root is not a directory", "root flags": "Invalid RCC node flags",
      "children overflow": "RCC child range exceeds tree", "root cycle": "RCC tree contains a cycle or shared child",
      "child flags": "Invalid RCC node flags", "name pointer": "Resource structure is truncated or out of bounds",
      "name length": "Resource structure is truncated or out of bounds", "name hash": "RCC name hash mismatch",
      "path separator": "Invalid RCC path component", "empty name": "Invalid RCC path component",
      "data pointer": "Resource structure is truncated or out of bounds", "data length": "RCC payload exceeds data table"
    }[label]);
  });
}

const truncatedRcc = embeddedResourceFixture("oracle-v3.rcc");
for (let size = 0; size < truncatedRcc.length; size += 1) {
  void test(`rejects truncated RCC prefix ${size} without throwing`, async () => {
    const result = await decodeRcc(new MockFile(truncatedRcc.subarray(0, size)), 0, size);
    assert.equal(result.value, null, `prefix ${size}`);
  });
}

void test("rejects an unconfirmed RCC signature without throwing", async () => {
  const result = await decodeRcc(new MockFile(new TextEncoder().encode("qres")), 0, 4);
  assert.equal(result.value, null);
  assert.match(result.issues.join(" "), /truncated/);
});
