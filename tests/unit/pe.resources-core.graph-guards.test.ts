"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildResourceTree } from "../../analyzers/pe/resources/core.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  IMAGE_RESOURCE_DATA_ENTRY_SIZE,
  createResourceDirectoryFixture,
  IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_SIZE,
  resourceNameString,
  resourceSubdirectory
} from "../helpers/pe-resource-fixture.js";

const FIXTURE_RESOURCE_RVA = 1;

const generatedResourceLabel = (index: number): string => index.toString(36);

const buildFixtureResourceDirectory = (size: number) => [
  { name: "RESOURCE", rva: FIXTURE_RESOURCE_RVA, size }
];

function mapFixtureRvaToStart(_value: number): number {
  return 0;
}

void test("buildResourceTree warns when a subdirectory target points into the string area", async () => {
  const generatedName = generatedResourceLabel(0);
  const fixture = createResourceDirectoryFixture(0x60);
  fixture.writeDirectory(0, 1, 1);
  // Microsoft PE/COFF specification, "Resource Directory String":
  // resource strings are stored after the last Resource Directory entry and before data entries.
  // Microsoft PE/COFF specification, "Resource Directory Entries":
  // Subdirectory Offset points to another resource directory table.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-string
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
  fixture.writeDirectoryEntry(
    IMAGE_RESOURCE_DIRECTORY_SIZE,
    resourceNameString(0x30),
    0
  );
  fixture.writeDirectoryEntry(
    IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
    3,
    resourceSubdirectory(0x30)
  );
  fixture.writeUtf16Label(0x30, generatedName);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
  );
  assert.ok(tree);

  assert.match((tree.issues || []).join(" "), /subdirectory.*string area|resource string/i);
});

void test("buildResourceTree warns when multiple parents reference the same subdirectory", async () => {
  const fixture = createResourceDirectoryFixture(0x90);
  fixture.writeDirectory(0, 0, 2);
  // Inference from the Microsoft PE/COFF .rsrc tree model:
  // the section is a tree of Type/Name/Language nodes, so sharing one child table
  // between multiple parents violates the tree shape.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  fixture.writeDirectoryEntry(0x10, 3, resourceSubdirectory(0x20));
  fixture.writeDirectoryEntry(0x18, 5, resourceSubdirectory(0x20));
  fixture.writeDirectory(0x20, 0, 1);
  fixture.writeDirectoryEntry(0x30, 1, resourceSubdirectory(0x40));
  fixture.writeDirectory(0x40, 0, 1);
  fixture.writeDirectoryEntry(0x50, 0x00000409, 0x00000060);
  fixture.writeDataEntry(0x60, 0x00002000, 0x10, 0x000004b0);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
  );
  assert.ok(tree);

  assert.match((tree.issues || []).join(" "), /subdirectory.*multiple|shared subdirectory/i);
});

void test("buildResourceTree skips repeated traversal when multiple parents re-enter one subdirectory", async () => {
  const fixture = createResourceDirectoryFixture(0x90);
  fixture.writeDirectory(0, 0, 2);
  fixture.writeDirectoryEntry(0x10, 3, resourceSubdirectory(0x20));
  fixture.writeDirectoryEntry(0x18, 5, resourceSubdirectory(0x20));
  fixture.writeDirectory(0x20, 0, 1);
  fixture.writeDirectoryEntry(0x30, 1, resourceSubdirectory(0x40));
  fixture.writeDirectory(0x40, 0, 1);
  fixture.writeDirectoryEntry(0x50, 0x00000409, 0x00000060);
  fixture.writeDataEntry(0x60, 0x00002000, 0x10, 0x000004b0);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [
    { typeName: "ICON", kind: "id", leafCount: 1 },
    { typeName: "DIALOG", kind: "id", leafCount: 0 }
  ]);
  assert.deepStrictEqual(tree.paths, [
    {
      nodes: [
        { id: 3, name: null },
        { id: 1, name: null },
        { id: 0x00000409, name: null }
      ],
      dataRVA: 0x00002000,
      size: 0x10,
      codePage: 0x000004b0,
      reserved: 0
    }
  ]);
  assert.match((tree.issues || []).join(" "), /re-enters|multiple parent paths|multiple parents/i);
});

void test("buildResourceTree warns when a subdirectory entry points to its own table", async () => {
  const fixture = createResourceDirectoryFixture(0x40);
  fixture.writeDirectory(0, 0, 1);
  // Inference from the Microsoft PE/COFF .rsrc tree model:
  // a directory entry that points back to the same table creates a cycle instead of a tree.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  fixture.writeDirectoryEntry(0x10, 3, resourceSubdirectory(0));

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
  );
  assert.ok(tree);

  assert.match((tree.issues || []).join(" "), /points to itself|cycle/i);
});

void test("buildResourceTree warns when a subdirectory target points into a resource data entry", async () => {
  const fixture = createResourceDirectoryFixture(0xa0);
  fixture.writeDirectory(0, 0, 2);
  // Microsoft PE/COFF specification, "Resource Directory Entries":
  // Subdirectory Offset points to another resource directory table.
  // Microsoft PE/COFF specification, "Resource Data Entry":
  // Resource Data entries are leaf descriptions, not directory tables.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-data-entry
  fixture.writeDirectoryEntry(0x10, 3, resourceSubdirectory(0x20));
  fixture.writeDirectoryEntry(0x18, 5, resourceSubdirectory(0x60));
  fixture.writeDirectory(0x20, 0, 1);
  fixture.writeDirectoryEntry(0x30, 1, resourceSubdirectory(0x40));
  fixture.writeDirectory(0x40, 0, 1);
  fixture.writeDirectoryEntry(0x50, 0x00000409, 0x00000060);
  fixture.writeDataEntry(0x60, 0x00002000, 0x10, 0x000004b0);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
  );
  assert.ok(tree);

  assert.match((tree.issues || []).join(" "), /subdirectory.*data entry|resource data entry/i);
});

void test("buildResourceTree warns when resource data payload ranges overlap", async () => {
  const fixture = createResourceDirectoryFixture(0xc0);
  fixture.writeDirectory(0, 0, 1);
  // Microsoft PE/COFF specification, "Resource Data":
  // Resource Data Descriptions delimit the individual regions of resource data.
  // Overlapping regions violate that delimitation.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  fixture.writeDirectoryEntry(0x10, 3, resourceSubdirectory(0x20));
  fixture.writeDirectory(0x20, 0, 2);
  fixture.writeDirectoryEntry(0x30, 1, resourceSubdirectory(0x40));
  fixture.writeDirectoryEntry(0x38, 2, resourceSubdirectory(0x60));
  fixture.writeDirectory(0x40, 0, 1);
  fixture.writeDirectoryEntry(0x50, 0x00000409, 0x00000080);
  fixture.writeDirectory(0x60, 0, 1);
  fixture.writeDirectoryEntry(0x70, 0x0000040a, 0x00000090);
  fixture.writeDataEntry(0x80, 0x00002000, 0x20, 0x000004b0);
  fixture.writeDataEntry(0x90, 0x00002010, 0x20, 0x000004b0);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
  );
  assert.ok(tree);

  assert.match((tree.issues || []).join(" "), /payload.*overlap|resource data.*overlap/i);
});

void test("buildResourceTree preserves valid resource paths deeper than the Windows three-level convention", async () => {
  const rootDirectoryOffset = 0;
  const rootEntryOffset = rootDirectoryOffset + IMAGE_RESOURCE_DIRECTORY_SIZE;
  const nameDirectoryOffset = rootEntryOffset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const nameEntryOffset = nameDirectoryOffset + IMAGE_RESOURCE_DIRECTORY_SIZE;
  const languageDirectoryOffset = nameEntryOffset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const languageEntryOffset = languageDirectoryOffset + IMAGE_RESOURCE_DIRECTORY_SIZE;
  const extraDirectoryOffset = languageEntryOffset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const extraEntryOffset = extraDirectoryOffset + IMAGE_RESOURCE_DIRECTORY_SIZE;
  const dataEntryOffset = extraEntryOffset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const fixture = createResourceDirectoryFixture(dataEntryOffset + IMAGE_RESOURCE_DATA_ENTRY_SIZE);

  fixture.writeDirectory(rootDirectoryOffset, 0, 1);
  fixture.writeDirectoryEntry(rootEntryOffset, 3, resourceSubdirectory(nameDirectoryOffset));
  fixture.writeDirectory(nameDirectoryOffset, 0, 1);
  fixture.writeDirectoryEntry(nameEntryOffset, 7, resourceSubdirectory(languageDirectoryOffset));
  fixture.writeDirectory(languageDirectoryOffset, 0, 1);
  // Microsoft PE/COFF specification, ".rsrc Section":
  // the general design can incorporate 2**31 levels; Type/Name/Language is the Windows convention,
  // not a hard format limit.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  fixture.writeDirectoryEntry(languageEntryOffset, 0x00000409, resourceSubdirectory(extraDirectoryOffset));
  fixture.writeDirectory(extraDirectoryOffset, 0, 1);
  fixture.writeDirectoryEntry(extraEntryOffset, 0x200, dataEntryOffset);
  fixture.writeDataEntry(dataEntryOffset, 0x00002000, 0x10, 0x000004b0);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
  );
  assert.ok(tree);

  assert.deepEqual(tree.paths, [
    {
      nodes: [
        { id: 3, name: null },
        { id: 7, name: null },
        { id: 0x00000409, name: null },
        { id: 0x200, name: null }
      ],
      dataRVA: 0x00002000,
      size: 0x10,
      codePage: 0x000004b0,
      reserved: 0
    }
  ]);
  assert.equal(
    (tree.issues || []).some(issue => /language entry.*subdirectory/i.test(issue)),
    false
  );
});
