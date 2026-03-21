"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildResourceTree } from "../../analyzers/pe/resources-core.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const IMAGE_RESOURCE_DIRECTORY_SIZE = 16; // IMAGE_RESOURCE_DIRECTORY
const IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE = 8; // IMAGE_RESOURCE_DIRECTORY_ENTRY
const IMAGE_RESOURCE_DATA_ENTRY_SIZE = 16; // IMAGE_RESOURCE_DATA_ENTRY
const RESOURCE_DIRECTORY_FLAG_MASK = 0x80000000;

const resourceDataDirectory = (rva: number, size: number) => [{ name: "RESOURCE", rva, size }];
const resourceNameString = (relativeOffset: number): number =>
  RESOURCE_DIRECTORY_FLAG_MASK | relativeOffset;
const resourceSubdirectory = (relativeOffset: number): number =>
  RESOURCE_DIRECTORY_FLAG_MASK | relativeOffset;

const writeUtf16Text = (bytes: Uint8Array, offset: number, text: string): void => {
  for (let index = 0; index < text.length; index += 1) {
    const codeUnit = text.charCodeAt(index);
    bytes[offset + index * 2] = codeUnit & 0xff;
    bytes[offset + index * 2 + 1] = codeUnit >>> 8;
  }
};
const createResourceDirectoryFixture = (fileSize: number): {
  bytes: Uint8Array;
  writeDirectory: (offset: number, namedCount: number, idCount: number) => void;
  writeDirectoryEntry: (offset: number, nameField: number, targetField: number) => void;
  writeUtf16Label: (offset: number, text: string, declaredLength?: number) => void;
  writeDataEntry: (
    offset: number,
    dataRva: number,
    size: number,
    codePage: number,
    reserved?: number
  ) => void;
} => {
  const bytes = new Uint8Array(fileSize).fill(0);
  const view = new DataView(bytes.buffer);

  const writeDirectory = (offset: number, namedCount: number, idCount: number): void => {
    view.setUint16(offset + 12, namedCount, true);
    view.setUint16(offset + 14, idCount, true);
  };

  const writeDirectoryEntry = (offset: number, nameField: number, targetField: number): void => {
    view.setUint32(offset, nameField, true);
    view.setUint32(offset + Uint32Array.BYTES_PER_ELEMENT, targetField, true);
  };

  const writeUtf16Label = (offset: number, text: string, declaredLength = text.length): void => {
    view.setUint16(offset, declaredLength, true);
    writeUtf16Text(bytes, offset + Uint16Array.BYTES_PER_ELEMENT, text);
  };

  const writeDataEntry = (
    offset: number,
    dataRva: number,
    size: number,
    codePage: number,
    reserved = 0
  ): void => {
    view.setUint32(offset, dataRva, true);
    view.setUint32(offset + 4, size, true);
    view.setUint32(offset + 8, codePage, true);
    view.setUint32(offset + 12, reserved, true);
  };

  return { bytes, writeDirectory, writeDirectoryEntry, writeUtf16Label, writeDataEntry };
};
const parseResourceTreeFixture = async (
  bytes: Uint8Array,
  resourceRva: number,
  resourceSize: number,
  rvaToOff: (value: number) => number | null,
  fileName = "resource.bin",
  addCoverageRegion: (label: string, start: number, size: number) => void = () => {}
) => expectDefined(await buildResourceTree(new MockFile(bytes, fileName),
  resourceDataDirectory(resourceRva, resourceSize), rvaToOff, addCoverageRegion));

void test("buildResourceTree returns null for missing or unmapped resource trees", async () => {
  const file = new MockFile(new Uint8Array(0));
  const noDir = await buildResourceTree(file, [], () => 0, () => {});
  assert.strictEqual(noDir, null);
  const unmapped = await buildResourceTree(
    file,
    resourceDataDirectory(0x200, 32),
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
  const fixture = createResourceDirectoryFixture(0xd0);
  const sparseSegments = [
    {
      fileOffset: 0x00,
      relativeOffset: 0x00,
      length: IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
    },
    {
      fileOffset: 0x40,
      relativeOffset: 0x20,
      length: IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
    },
    {
      fileOffset: 0x80,
      relativeOffset: 0x40,
      length: IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
    },
    { fileOffset: 0xc0, relativeOffset: 0x60, length: IMAGE_RESOURCE_DATA_ENTRY_SIZE }
  ];

  fixture.writeDirectory(0x00, 0, 1);
  fixture.writeDirectoryEntry(0x10, 3, resourceSubdirectory(0x20));
  fixture.writeDirectory(0x40, 0, 1);
  fixture.writeDirectoryEntry(0x50, 1, resourceSubdirectory(0x40));
  fixture.writeDirectory(0x80, 0, 1);
  fixture.writeDirectoryEntry(0x90, 0x00000409, 0x00000060);
  fixture.writeDataEntry(0xc0, 0x00002000, 0x10, 0x000004b0);

  const sparseRvaToOff = (rva: number): number | null => {
    const relativeOffset = rva - resourceRva;
    for (const segment of sparseSegments) {
      if (
        relativeOffset >= segment.relativeOffset &&
        relativeOffset < segment.relativeOffset + segment.length
      ) {
        return segment.fileOffset + (relativeOffset - segment.relativeOffset);
      }
    }
    return null;
  };

  const tree = await parseResourceTreeFixture(
    fixture.bytes,
    resourceRva,
    0x70,
    sparseRvaToOff,
    "resource-sparse-layout.bin"
  );

  assert.deepStrictEqual(tree.top, [{ typeName: "ICON", kind: "id", leafCount: 1 }]);
  const iconDetail = expectDefined(tree.detail[0]);
  const iconEntry = expectDefined(iconDetail.entries[0]);
  assert.strictEqual(expectDefined(iconEntry.langs[0]).dataRVA, 0x2000);
  assert.deepStrictEqual(tree.issues || [], []);
});
