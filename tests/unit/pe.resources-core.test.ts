"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildResourceTree } from "../../analyzers/pe/resources-core.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import {
  createSparseResourceRvaToOffset,
  createResourceDirectoryFixture,
  IMAGE_RESOURCE_DATA_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_SIZE,
  parseResourceTreeFixture,
  resourceNameString,
  resourceSubdirectory
} from "../helpers/pe-resource-fixture.js";

void test("buildResourceTree returns null for missing or unmapped resource trees", async () => {
  const file = new MockFile(new Uint8Array(0));
  const noDir = await buildResourceTree(file, [], () => 0, () => {});
  assert.strictEqual(noDir, null);
  const unmapped = await buildResourceTree(
    file,
    [{ name: "RESOURCE", rva: 0x200, size: 32 }],
    () => null,
    () => {}
  );
  assert.strictEqual(unmapped, null);
});
void test("buildResourceTree reports a truncated root directory header at EOF", async () => {
  const bytes = new Uint8Array(IMAGE_RESOURCE_DIRECTORY_SIZE / 2).fill(0);
  const tree = await parseResourceTreeFixture(
    bytes,
    1,
    IMAGE_RESOURCE_DIRECTORY_SIZE,
    () => 0,
    "resource-root-truncated.bin"
  );

  assert.deepStrictEqual(tree.top, []);
  assert.deepStrictEqual(tree.detail, []);
  assert.match((tree.issues || []).join(" "), /truncated/i);
});
void test("buildResourceTree preserves full numeric resource IDs", async () => {
  const fixture = createResourceDirectoryFixture(
    IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
  );
  fixture.writeDirectory(0, 0, 1);
  // PE/COFF resource directory entries store numeric IDs in the full 32-bit field
  // when the high bit is clear.
  // Use a value above 0xffff so truncation to 16 bits is immediately visible (0x12345 = 74565).
  fixture.writeDirectoryEntry(IMAGE_RESOURCE_DIRECTORY_SIZE, 0x00012345, 0);

  const tree = await parseResourceTreeFixture(fixture.bytes, 1, fixture.bytes.length, () => 0);
  assert.deepStrictEqual(tree.top, [{ typeName: "TYPE_74565", kind: "id", leafCount: 0 }]);
});

void test("buildResourceTree preserves embedded NUL code units in length-prefixed resource names", async () => {
  const fixture = createResourceDirectoryFixture(
    IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE + 8
  );
  fixture.writeDirectory(0, 1, 0);
  fixture.writeDirectoryEntry(
    IMAGE_RESOURCE_DIRECTORY_SIZE,
    resourceNameString(0x18),
    0
  );
  // PE resource directory strings are length-prefixed UTF-16, not NUL-terminated.
  fixture.writeUtf16Label(0x18, "A\0B");

  const tree = await parseResourceTreeFixture(
    fixture.bytes,
    1,
    fixture.bytes.length,
    () => 0,
    "resource-name-embedded-nul.bin"
  );

  const typeName = expectDefined(tree.top[0]).typeName;
  assert.strictEqual(typeName.length, 3);
  assert.strictEqual(typeName.charCodeAt(0), 0x41);
  assert.strictEqual(typeName.charCodeAt(1), 0x0000);
  assert.strictEqual(typeName.charCodeAt(2), 0x42);
});
void test("buildResourceTree ignores entries outside the declared resource span", async () => {
  const fixture = createResourceDirectoryFixture(0x40);
  fixture.writeDirectory(0, 0, 1);
  // The resource data directory declares only the 16-byte root header.
  fixture.writeDirectoryEntry(IMAGE_RESOURCE_DIRECTORY_SIZE, 3, resourceSubdirectory(0x20));

  const tree = await parseResourceTreeFixture(
    fixture.bytes,
    1,
    IMAGE_RESOURCE_DIRECTORY_SIZE,
    () => 0,
    "resource-oob-root.bin"
  );

  assert.deepStrictEqual(tree.top, []);
  assert.deepStrictEqual(tree.detail, []);
  assert.match((tree.issues || []).join(" "), /declared span/i);
});

void test("buildResourceTree parses nested directories and skips truncated labels", async () => {
  const fixture = createResourceDirectoryFixture(0x130);
  fixture.writeDirectory(0, 1, 1);
  fixture.writeDirectoryEntry(0x10, 3, resourceSubdirectory(0x20));
  fixture.writeDirectoryEntry(0x18, resourceNameString(0x120), 0);
  fixture.writeDirectory(0x20, 1, 0);
  fixture.writeDirectoryEntry(0x30, resourceNameString(0x40), resourceSubdirectory(0x60));
  fixture.writeUtf16Label(0x40, "Test");
  fixture.writeDirectory(0x60, 0, 1);
  fixture.writeDirectoryEntry(0x70, 0x00000409, 0x00000080);
  fixture.writeDataEntry(0x80, 0x00002000, 0x10, 0x000004b0);

  const coverage: Array<{ label: string; start: number; size: number }> = [];
  const tree = await parseResourceTreeFixture(
    fixture.bytes,
    1,
    0x120,
    () => 0,
    "pe-resources.bin",
    (label, start, size) => coverage.push({ label, start, size })
  );

  assert.strictEqual(tree.top.length, 2);
  assert.deepStrictEqual(tree.top[0], { typeName: "ICON", kind: "id", leafCount: 1 });
  assert.deepStrictEqual(tree.top[1], { typeName: "", kind: "name", leafCount: 0 });

  const iconDetail = expectDefined(tree.detail.find(entry => entry.typeName === "ICON"));
  const iconEntry = expectDefined(iconDetail.entries[0]);
  const iconLang = expectDefined(iconEntry.langs[0]);
  assert.strictEqual(iconEntry.name, "Test");
  assert.deepStrictEqual(iconLang, {
    lang: 0x409,
    size: 0x10,
    codePage: 0x4b0,
    dataRVA: 0x2000,
    reserved: 0
  });
  assert.strictEqual(expectDefined(coverage[0]).label, "RESOURCE directory");
  assert.match((tree.issues || []).join(" "), /string name/i);
});

void test("buildResourceTree accepts data entries ending at the resource boundary", async () => {
  const fixture = createResourceDirectoryFixture(0x70);
  fixture.writeDirectory(0, 0, 1);
  fixture.writeDirectoryEntry(0x10, 0x00000003, resourceSubdirectory(0x20));
  fixture.writeDirectory(0x20, 0, 1);
  fixture.writeDirectoryEntry(0x30, 0x00000001, resourceSubdirectory(0x40));
  fixture.writeDirectory(0x40, 0, 1);
  fixture.writeDirectoryEntry(0x50, 0x00000409, 0x00000060);
  fixture.writeDataEntry(0x60, 0x00002000, 0x10, 0x000004b0);

  const tree = await parseResourceTreeFixture(
    fixture.bytes,
    1,
    fixture.bytes.length,
    () => 0,
    "resource-boundary.bin"
  );

  assert.deepStrictEqual(tree.top, [{ typeName: "ICON", kind: "id", leafCount: 1 }]);
  const iconDetail = expectDefined(tree.detail[0]);
  const iconEntry = expectDefined(iconDetail.entries[0]);
  assert.strictEqual(expectDefined(iconEntry.langs[0]).dataRVA, 0x2000);
});

void test("buildResourceTree reports non-zero reserved fields in IMAGE_RESOURCE_DATA_ENTRY", async () => {
  const fixture = createResourceDirectoryFixture(0x70);
  fixture.writeDirectory(0, 0, 1);
  fixture.writeDirectoryEntry(0x10, 0x00000003, resourceSubdirectory(0x20));
  fixture.writeDirectory(0x20, 0, 1);
  fixture.writeDirectoryEntry(0x30, 0x00000001, resourceSubdirectory(0x40));
  fixture.writeDirectory(0x40, 0, 1);
  fixture.writeDirectoryEntry(0x50, 0x00000409, 0x00000060);
  fixture.writeDataEntry(0x60, 0x00002000, 0x10, 0x000004b0, 1);

  const tree = await parseResourceTreeFixture(
    fixture.bytes,
    1,
    fixture.bytes.length,
    () => 0,
    "resource-reserved-nonzero.bin"
  );

  const iconDetail = expectDefined(tree.detail[0]);
  const iconEntry = expectDefined(iconDetail.entries[0]);
  assert.strictEqual(expectDefined(iconEntry.langs[0]).reserved, 1);
  assert.match((tree.issues || []).join(" "), /reserved|must be 0|non-zero/i);
});

void test("buildResourceTree walks a small resource directory", async () => {
  const resourceRva = 0x10;
  const fixture = createResourceDirectoryFixture(256);
  fixture.writeDirectory(resourceRva, 0, 1);
  fixture.writeDirectoryEntry(
    resourceRva + IMAGE_RESOURCE_DIRECTORY_SIZE,
    3,
    resourceSubdirectory(0x20)
  );

  const nameDirectoryOffset = resourceRva + 0x20;
  fixture.writeDirectory(nameDirectoryOffset, 0, 1);
  fixture.writeDirectoryEntry(
    nameDirectoryOffset + IMAGE_RESOURCE_DIRECTORY_SIZE,
    1,
    resourceSubdirectory(0x40)
  );

  const languageDirectoryOffset = resourceRva + 0x40;
  fixture.writeDirectory(languageDirectoryOffset, 0, 1);
  fixture.writeDirectoryEntry(languageDirectoryOffset + IMAGE_RESOURCE_DIRECTORY_SIZE, 0, 0x60);
  fixture.writeDataEntry(resourceRva + 0x60, 0x1000, 16, 1252);

  const tree = await parseResourceTreeFixture(fixture.bytes, resourceRva, 0x80, value => value);

  assert.equal(tree.top.length, 1);
  assert.equal(expectDefined(tree.top[0]).leafCount, 1);
  const detailEntry = expectDefined(tree.detail[0]);
  const lang = expectDefined(expectDefined(detailEntry.entries[0]).langs[0]);
  assert.equal(lang.size, 16);
});

void test("buildResourceTree resolves directory-relative offsets through rvaToOff", async () => {
  const resourceRva = 0x1000;
  const resourcePayloadRva = 0x2000;
  const fixture = createResourceDirectoryFixture(0xe0);
  const sparseSegments = [
    {
      fileOffset: 0x00,
      rvaStart: resourceRva,
      length: IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
    },
    {
      fileOffset: 0x40,
      rvaStart: resourceRva + 0x20,
      length: IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
    },
    {
      fileOffset: 0x80,
      rvaStart: resourceRva + 0x40,
      length: IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
    },
    {
      fileOffset: 0xc0,
      rvaStart: resourceRva + 0x60,
      length: IMAGE_RESOURCE_DATA_ENTRY_SIZE
    },
    { fileOffset: 0xd0, rvaStart: resourcePayloadRva, length: 0x10 }
  ];

  fixture.writeDirectory(0x00, 0, 1);
  fixture.writeDirectoryEntry(0x10, 3, resourceSubdirectory(0x20));
  fixture.writeDirectory(0x40, 0, 1);
  fixture.writeDirectoryEntry(0x50, 1, resourceSubdirectory(0x40));
  fixture.writeDirectory(0x80, 0, 1);
  fixture.writeDirectoryEntry(0x90, 0x00000409, 0x00000060);
  fixture.writeDataEntry(0xc0, resourcePayloadRva, 0x10, 0x000004b0);

  const tree = await parseResourceTreeFixture(
    fixture.bytes,
    resourceRva,
    0x70,
    createSparseResourceRvaToOffset(sparseSegments),
    "resource-sparse-layout.bin"
  );

  assert.deepStrictEqual(tree.top, [{ typeName: "ICON", kind: "id", leafCount: 1 }]);
  const iconDetail = expectDefined(tree.detail[0]);
  const iconEntry = expectDefined(iconDetail.entries[0]);
  assert.strictEqual(expectDefined(iconEntry.langs[0]).dataRVA, resourcePayloadRva);
  assert.deepStrictEqual(tree.issues || [], []);
});
