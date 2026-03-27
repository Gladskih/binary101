"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildResourceTree } from "../../analyzers/pe/resources/core.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  createResourceDirectoryFixture,
  IMAGE_RESOURCE_DATA_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_SIZE,
  resourceNameString
} from "../helpers/pe-resource-fixture.js";

const FIXTURE_RESOURCE_RVA = 1;

// Base-36 keeps generated labels short; the tests care only about identity/order,
// not about any particular resource-name spelling.
const generatedResourceLabel = (index: number): string => index.toString(36);

const buildFixtureResourceDirectory = (size: number) => [
  // buildResourceTree locates the PE resource span by the canonical RESOURCE directory name.
  { name: "RESOURCE", rva: FIXTURE_RESOURCE_RVA, size }
];

function mapFixtureRvaToStart(_value: number): number {
  return 0;
}

function ignoreCoverage(_label: string, _start: number, _size: number): void {}

void test("buildResourceTree warns when a named resource entry appears after an ID entry", async () => {
  const firstRootEntryOffset = IMAGE_RESOURCE_DIRECTORY_SIZE;
  const generatedName = generatedResourceLabel(0);
  // A one-character UTF-16 resource name needs 2 bytes for the length prefix
  // plus 2 bytes for the code unit payload.
  const nameStringOffset = 0x30;

  // 0x40 is the smallest fixture that still fits:
  // - the 16-byte root directory header,
  // - two 8-byte root entries,
  // - a 4-byte length-prefixed UTF-16 string at 0x30.
  const fixture = createResourceDirectoryFixture(0x40);
  fixture.writeDirectory(0, 1, 1);
  // Microsoft PE/COFF specification, "The .rsrc Section" -> "Resource Directory Table":
  // NumberOfNameEntries entries are followed immediately by NumberOfIdEntries entries.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  // Microsoft PE/COFF specification, "Resource Directory Entries":
  // all Name entries precede all ID entries, and each group is sorted in ascending order.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
  // Zero target is enough here because this regression exercises only root-entry ordering,
  // not child directory traversal.
  fixture.writeDirectoryEntry(
    firstRootEntryOffset,
    5, // RT_DIALOG in Win32 resource type ids.
    0
  );
  fixture.writeDirectoryEntry(
    firstRootEntryOffset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
    resourceNameString(nameStringOffset),
    0
  );
  fixture.writeUtf16Label(nameStringOffset, generatedName);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [
    { typeName: "DIALOG", kind: "id", leafCount: 0 },
    { typeName: generatedName, kind: "name", leafCount: 0 }
  ]);
  assert.match(
    (tree.issues || []).join(" "),
    /name entries.*id entries|named entries.*before.*id entries|sorted/i
  );
});

void test("buildResourceTree warns when ID entries are not sorted in ascending order", async () => {
  const firstRootEntryOffset = IMAGE_RESOURCE_DIRECTORY_SIZE;
  const fixture = createResourceDirectoryFixture(
    IMAGE_RESOURCE_DIRECTORY_SIZE + 2 * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
  );
  fixture.writeDirectory(0, 0, 2);
  // Microsoft PE/COFF specification, "Resource Directory Entries":
  // all Name entries precede all ID entries, and each group is sorted in ascending order.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
  // Use values above the well-known RT_* range so the parser keeps TYPE_* labels
  // and the assertion stays focused on numeric ordering.
  fixture.writeDirectoryEntry(firstRootEntryOffset, 0x00000101, 0);
  fixture.writeDirectoryEntry(firstRootEntryOffset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE, 0x00000100, 0);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [
    { typeName: "TYPE_257", kind: "id", leafCount: 0 },
    { typeName: "TYPE_256", kind: "id", leafCount: 0 }
  ]);
  assert.match((tree.issues || []).join(" "), /sorted|ascending/i);
});

void test("buildResourceTree warns when named entries are not sorted by string value", async () => {
  const firstRootEntryOffset = IMAGE_RESOURCE_DIRECTORY_SIZE;
  const secondRootEntryOffset = firstRootEntryOffset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const laterSortName = generatedResourceLabel(1);
  const earlierSortName = generatedResourceLabel(0);
  const firstNameStringOffset = IMAGE_RESOURCE_DIRECTORY_SIZE + 2 * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const secondNameStringOffset = firstNameStringOffset + 4;
  const fixture = createResourceDirectoryFixture(secondNameStringOffset + 4);
  fixture.writeDirectory(0, 2, 0);
  // Microsoft PE/COFF specification, "Resource Directory Entries":
  // name entries are sorted in ascending order by case-sensitive string.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
  fixture.writeDirectoryEntry(firstRootEntryOffset, resourceNameString(firstNameStringOffset), 0);
  fixture.writeDirectoryEntry(secondRootEntryOffset, resourceNameString(secondNameStringOffset), 0);
  fixture.writeUtf16Label(firstNameStringOffset, laterSortName);
  fixture.writeUtf16Label(secondNameStringOffset, earlierSortName);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [
    { typeName: laterSortName, kind: "name", leafCount: 0 },
    { typeName: earlierSortName, kind: "name", leafCount: 0 }
  ]);
  assert.match((tree.issues || []).join(" "), /sorted|ascending/i);
});

void test("buildResourceTree warns when resource directory Characteristics is non-zero", async () => {
  const firstRootEntryOffset = IMAGE_RESOURCE_DIRECTORY_SIZE;
  const fixture = createResourceDirectoryFixture(
    IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
  );
  const view = new DataView(fixture.bytes.buffer);
  fixture.writeDirectory(0, 0, 1);
  // Microsoft PE/COFF specification, "Resource Directory Table":
  // Characteristics are resource flags reserved for future use and currently set to zero.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  view.setUint32(0, 1, true);
  fixture.writeDirectoryEntry(firstRootEntryOffset, 0x00000100, 0);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.match((tree.issues || []).join(" "), /characteristics|reserved|zero/i);
});

void test("buildResourceTree warns when a top-level type entry points directly to data", async () => {
  const firstRootEntryOffset = IMAGE_RESOURCE_DIRECTORY_SIZE;
  const dataEntryOffset = IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const fixture = createResourceDirectoryFixture(dataEntryOffset + IMAGE_RESOURCE_DATA_ENTRY_SIZE);
  fixture.writeDirectory(0, 0, 1);
  // Microsoft PE/COFF specification, "The .rsrc Section":
  // the first table lists top-level Type nodes, and its entries point to second-level tables.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  fixture.writeDirectoryEntry(firstRootEntryOffset, 3, dataEntryOffset); // RT_ICON
  fixture.writeDataEntry(dataEntryOffset, 0x00002000, 0x10, 0x000004b0);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [{ typeName: "ICON", kind: "id", leafCount: 0 }]);
  assert.match((tree.issues || []).join(" "), /subdirectory|second-level|type entry/i);
});

void test("buildResourceTree warns when a resource name string offset is not word-aligned", async () => {
  const firstRootEntryOffset = IMAGE_RESOURCE_DIRECTORY_SIZE;
  const generatedName = generatedResourceLabel(0);
  const misalignedNameStringOffset =
    IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE + 1;
  const fixture = createResourceDirectoryFixture(misalignedNameStringOffset + 4);
  fixture.writeDirectory(0, 1, 0);
  // Microsoft PE/COFF specification, "Resource Directory String":
  // these Unicode strings are word-aligned.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-string
  fixture.writeDirectoryEntry(firstRootEntryOffset, resourceNameString(misalignedNameStringOffset), 0);
  fixture.writeUtf16Label(misalignedNameStringOffset, generatedName);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [{ typeName: generatedName, kind: "name", leafCount: 0 }]);
  assert.match((tree.issues || []).join(" "), /word-aligned|aligned/i);
});
