import assert from "node:assert/strict";
import { test } from "node:test";
import { validateGvdbHierarchy } from "../../../../analyzers/embedded-resources/gvdb-hierarchy.js";
import { decodeGResource } from "../../../../analyzers/embedded-resources/gresource.js";
import { minimalGResource } from "../../../fixtures/embedded-resource-builders.js";
import { MockFile } from "../../../helpers/mock-file.js";

const entries = async () => {
  const file = new MockFile(minimalGResource());
  const result = await decodeGResource(file, 0, file.size);
  assert.ok(result.value);
  return result.value.entries;
};

void test("validates all hash buckets and the complete directory hierarchy", async () => {
  const items = await entries();
  assert.doesNotThrow(() => validateGvdbHierarchy(items, [0], [], 5));
  assert.throws(() => validateGvdbHierarchy(items, [0, 0, 0], [], 5), /wrong hash bucket/);
  items[1]!.type = "L";
  assert.throws(() => validateGvdbHierarchy(items, [0], [], 5), /item type/);
  items[1]!.type = "v";
  items[1]!.name = "a/";
  items[1]!.hash = 193431428; // djb_hash("/a/") per GNOME gvdb-builder.c.
  assert.throws(() => validateGvdbHierarchy(items, [0], [], 5), /item type/);
});

void test("uses the correct bloom word and both independent bits for each key hash", async () => {
  const items = await entries();
  // GVDB bloom word index = (hash / 32) % count; bit indices = hash & 31 and (hash >> 5) & 31.
  assert.doesNotThrow(() => validateGvdbHierarchy(items, [0, 1], [0x00104000, 0x00200020], 5));
  assert.throws(() => validateGvdbHierarchy(items, [0, 1], [0x00104000, 0x00200000], 5),
    { message: "GVDB bloom filter excludes a resource" });
  assert.throws(() => validateGvdbHierarchy(items, [0, 1], [0x00104000, 0x00000020], 5),
    { message: "GVDB bloom filter excludes a resource" });
  assert.throws(() => validateGvdbHierarchy(items, [0, 2], [], 5),
    { message: "GVDB item is in the wrong hash bucket" });
});

void test("rejects duplicate children and invalid path fragments", async () => {
  const items = await entries();
  items.push({ ...items[1]! });
  items[0]!.children = [1, 2];
  assert.throws(() => validateGvdbHierarchy(items, [0], [], 5), /Duplicate/);
  items[2]!.name = "a/b";
  assert.throws(() => validateGvdbHierarchy(items, [0], [], 5), /path component/);
  items[0]!.children = [1];
  assert.throws(() => validateGvdbHierarchy(items, [0], [], 5), /unreachable/);
});

void test("does not identify an empty or non-resource GVDB database as GResource", async () => {
  const items = await entries();
  assert.throws(() => validateGvdbHierarchy([], [0], [], 5), /unique/);
  items[0]!.children = [];
  assert.throws(() => validateGvdbHierarchy(items.slice(0, 1), [0], [], 5), /no GResource file/);
  items[0]!.name = "other/";
  assert.throws(() => validateGvdbHierarchy(items, [0], [], 5), /unique/);
});
