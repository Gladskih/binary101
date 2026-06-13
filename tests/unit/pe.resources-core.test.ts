"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildResourceTree } from "../../analyzers/pe/resources/core.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  createResourceDirectoryFixture,
  IMAGE_RESOURCE_DIRECTORY_SIZE,
  resourceSubdirectory
} from "../helpers/pe-resource-fixture.js";

const RESOURCE_RVA = 0x1000;
// Microsoft PE format, ".rsrc Section": IMAGE_RESOURCE_DIRECTORY is 16 bytes.
const RESOURCE_DIRECTORY_HEADER_SIZE = 16;

const mapResourceRvaToOffset = (rva: number): number | null =>
  rva >= RESOURCE_RVA ? rva - RESOURCE_RVA : null;

void test("buildResourceTree returns null when the RESOURCE directory is absent or empty", async () => {
  const file = new MockFile(new Uint8Array(IMAGE_RESOURCE_DIRECTORY_SIZE));

  assert.strictEqual(await buildResourceTree(file, [], () => 0), null);
  assert.strictEqual(
    await buildResourceTree(file, [{ name: "RESOURCE", rva: 0, size: 0 }], () => 0),
    null
  );
});

void test("buildResourceTree returns warning results before parsing invalid resource spans", async () => {
  const file = new MockFile(new Uint8Array(IMAGE_RESOURCE_DIRECTORY_SIZE));
  const validDir = { name: "RESOURCE", rva: RESOURCE_RVA, size: IMAGE_RESOURCE_DIRECTORY_SIZE };

  const smallTree = await buildResourceTree(
    file,
    [{ name: "RESOURCE", rva: RESOURCE_RVA, size: 1 }],
    mapResourceRvaToOffset
  );
  const zeroRvaTree = await buildResourceTree(
    file,
    [{ name: "RESOURCE", rva: 0, size: 1 }],
    mapResourceRvaToOffset
  );
  const unmappedTree = await buildResourceTree(file, [validDir], () => null);
  const outsideTree = await buildResourceTree(new MockFile(new Uint8Array(1)), [validDir], () => 2);
  const eofTree = await buildResourceTree(new MockFile(new Uint8Array(1)), [validDir], () => 1);
  const negativeTree = await buildResourceTree(file, [validDir], () => -1);
  const zeroSizeTree = await buildResourceTree(
    file,
    [{ name: "RESOURCE", rva: RESOURCE_RVA, size: 0 }],
    mapResourceRvaToOffset
  );
  const smallDirectoryIssue =
    `Resource directory is smaller than IMAGE_RESOURCE_DIRECTORY `
    + `(${RESOURCE_DIRECTORY_HEADER_SIZE} bytes).`;

  assert.deepStrictEqual(smallTree?.issues, [smallDirectoryIssue]);
  assert.match((zeroRvaTree?.issues || []).join(" "), /rva is 0/i);
  assert.match((unmappedTree?.issues || []).join(" "), /does not map/i);
  assert.match((outsideTree?.issues || []).join(" "), /outside file data/i);
  assert.match((eofTree?.issues || []).join(" "), /outside file data/i);
  assert.match((negativeTree?.issues || []).join(" "), /outside file data/i);
  assert.deepStrictEqual(zeroSizeTree?.issues, [smallDirectoryIssue]);
});

void test("buildResourceTree selects the RESOURCE directory and parses a minimal root", async () => {
  const fixture = createResourceDirectoryFixture(IMAGE_RESOURCE_DIRECTORY_SIZE);
  fixture.writeDirectory(0, 0, 0);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    [
      { name: "DEBUG", rva: 0, size: 0 },
      { name: "RESOURCE", rva: RESOURCE_RVA, size: fixture.bytes.length }
    ],
    mapResourceRvaToOffset
  );

  assert.ok(tree);
  assert.strictEqual(tree.limitEnd, fixture.bytes.length);
  assert.deepStrictEqual(tree.directories?.map(directory => directory.offset), [0]);
  assert.deepStrictEqual(tree.top, []);
  assert.deepStrictEqual(tree.detail, []);
  assert.deepStrictEqual(tree.paths ?? [], []);
  assert.deepStrictEqual(tree.issues ?? [], []);
});

void test("buildResourceTree returns a parsed result when the root directory is truncated by EOF", async () => {
  const tree = await buildResourceTree(
    new MockFile(new Uint8Array(IMAGE_RESOURCE_DIRECTORY_SIZE / 2)),
    [{ name: "RESOURCE", rva: RESOURCE_RVA, size: IMAGE_RESOURCE_DIRECTORY_SIZE }],
    mapResourceRvaToOffset
  );

  assert.ok(tree);
  assert.deepStrictEqual(tree.directories ?? [], []);
  assert.deepStrictEqual(tree.top, []);
  assert.deepStrictEqual(tree.detail, []);
  assert.match((tree.issues ?? []).join(" "), /truncated by end of file/i);
});

void test("buildResourceTree assembles paths and validates resource layout", async () => {
  const fixture = createResourceDirectoryFixture(0x70);
  fixture.writeDirectory(0, 0, 1);
  fixture.writeDirectoryEntry(IMAGE_RESOURCE_DIRECTORY_SIZE, 3, resourceSubdirectory(0x20));
  fixture.writeDirectory(0x20, 0, 1);
  fixture.writeDirectoryEntry(0x20 + IMAGE_RESOURCE_DIRECTORY_SIZE, 9, 0x40);
  fixture.writeDataEntry(0x40, RESOURCE_RVA + 0x6e, 4, 1252);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    [{ name: "RESOURCE", rva: RESOURCE_RVA, size: fixture.bytes.length }],
    mapResourceRvaToOffset
  );

  assert.ok(tree);
  assert.strictEqual(tree.limitEnd, fixture.bytes.length);
  assert.deepStrictEqual(tree.top, [{ typeName: "ICON", kind: "id", leafCount: 0 }]);
  assert.deepStrictEqual(tree.detail, []);
  assert.deepStrictEqual(tree.paths, [{
    nodes: [{ id: 3, name: null }, { id: 9, name: null }],
    dataRVA: RESOURCE_RVA + 0x6e,
    dataFileOffset: 0x6e,
    size: 4,
    codePage: 1252,
    reserved: 0
  }]);
  assert.match((tree.issues ?? []).join(" "), /points directly to data/i);
  assert.match((tree.issues ?? []).join(" "), /outside the declared \.rsrc RVA span/i);
});
