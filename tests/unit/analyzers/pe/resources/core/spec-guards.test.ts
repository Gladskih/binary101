"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseResources } from "../../../../../../analyzers/pe/resources/index.js";
import { buildResourceTree } from "../../../../../../analyzers/pe/resources/core.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import {
  createResourceDirectoryFixture,
  IMAGE_RESOURCE_DATA_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_SIZE,
  resourceNameString,
  resourceSubdirectory
} from "../../../../../helpers/pe-resource-fixture.js";

const FIXTURE_RESOURCE_RVA = 1;

// Base-36 keeps generated labels short; the tests care only about identity/order,
// not about any particular resource-name spelling.
const generatedResourceLabel = (index: number): string => index.toString(36);

const buildFixtureResourceDirectory = (size: number) => [
  // buildResourceTree locates the PE resource span by the canonical RESOURCE directory name.
  { name: "RESOURCE", rva: FIXTURE_RESOURCE_RVA, size }
];

function mapFixtureRvaToStart(value: number): number {
  return value - FIXTURE_RESOURCE_RVA;
}

void test("buildResourceTree warns when a named resource entry appears after an ID entry", async () => {
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
    IMAGE_RESOURCE_DIRECTORY_SIZE,
    5, // RT_DIALOG in Win32 resource type ids.
    0
  );
  fixture.writeDirectoryEntry(
    IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
    resourceNameString(nameStringOffset),
    0
  );
  fixture.writeUtf16Label(nameStringOffset, generatedName);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
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

void test("buildResourceTree reports an unmappable resource directory base instead of silently returning null", async () => {
  const tree = await buildResourceTree(
    new MockFile(new Uint8Array(IMAGE_RESOURCE_DIRECTORY_SIZE).fill(0)),
    buildFixtureResourceDirectory(IMAGE_RESOURCE_DIRECTORY_SIZE),
    () => null
  );

  assert.ok(tree);
  assert.deepStrictEqual(tree?.top, []);
  assert.deepStrictEqual(tree?.detail, []);
  assert.match((tree?.issues || []).join(" "), /map|offset|rva/i);
});

void test("buildResourceTree preserves a non-zero directory that is smaller than IMAGE_RESOURCE_DIRECTORY", async () => {
  const tree = await buildResourceTree(
    new MockFile(new Uint8Array(IMAGE_RESOURCE_DIRECTORY_SIZE - 1).fill(0)),
    buildFixtureResourceDirectory(IMAGE_RESOURCE_DIRECTORY_SIZE - 1),
    mapFixtureRvaToStart
  );

  assert.ok(tree);
  assert.deepStrictEqual(tree?.top, []);
  assert.deepStrictEqual(tree?.detail, []);
  assert.match((tree?.issues || []).join(" "), /smaller|directory|16/i);
});

void test("buildResourceTree warns when ID entries are not sorted in ascending order", async () => {
  const fixture = createResourceDirectoryFixture(
    IMAGE_RESOURCE_DIRECTORY_SIZE + 2 * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
  );
  fixture.writeDirectory(0, 0, 2);
  // Microsoft PE/COFF specification, "Resource Directory Entries":
  // all Name entries precede all ID entries, and each group is sorted in ascending order.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
  // Use values above the well-known RT_* range so the parser keeps TYPE_* labels
  // and the assertion stays focused on numeric ordering.
  fixture.writeDirectoryEntry(IMAGE_RESOURCE_DIRECTORY_SIZE, 0x00000101, 0);
  fixture.writeDirectoryEntry(
    IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
    0x00000100,
    0
  );

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [
    { typeName: "TYPE_257", kind: "id", leafCount: 0 },
    { typeName: "TYPE_256", kind: "id", leafCount: 0 }
  ]);
  assert.match((tree.issues || []).join(" "), /sorted|ascending/i);
});

void test("buildResourceTree warns when named entries are not sorted by string value", async () => {
  const laterSortName = generatedResourceLabel(1);
  const earlierSortName = generatedResourceLabel(0);
  const firstNameStringOffset = IMAGE_RESOURCE_DIRECTORY_SIZE + 2 * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const secondNameStringOffset = firstNameStringOffset + 4;
  const fixture = createResourceDirectoryFixture(secondNameStringOffset + 4);
  fixture.writeDirectory(0, 2, 0);
  // Microsoft PE/COFF specification, "Resource Directory Entries":
  // name entries are sorted in ascending order by case-sensitive string.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
  fixture.writeDirectoryEntry(IMAGE_RESOURCE_DIRECTORY_SIZE, resourceNameString(firstNameStringOffset), 0);
  fixture.writeDirectoryEntry(
    IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
    resourceNameString(secondNameStringOffset),
    0
  );
  fixture.writeUtf16Label(firstNameStringOffset, laterSortName);
  fixture.writeUtf16Label(secondNameStringOffset, earlierSortName);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [
    { typeName: laterSortName, kind: "name", leafCount: 0 },
    { typeName: earlierSortName, kind: "name", leafCount: 0 }
  ]);
  assert.match((tree.issues || []).join(" "), /sorted|ascending/i);
});

void test("buildResourceTree warns when resource directory Characteristics is non-zero", async () => {
  const fixture = createResourceDirectoryFixture(
    IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
  );
  const view = new DataView(fixture.bytes.buffer);
  fixture.writeDirectory(0, 0, 1);
  // Microsoft PE/COFF specification, "Resource Directory Table":
  // Characteristics are resource flags reserved for future use and currently set to zero.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  view.setUint32(0, 1, true);
  fixture.writeDirectoryEntry(IMAGE_RESOURCE_DIRECTORY_SIZE, 0x00000100, 0);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
  );
  assert.ok(tree);

  assert.match((tree.issues || []).join(" "), /characteristics|reserved|zero/i);
});

void test("buildResourceTree warns when a top-level type entry points directly to data", async () => {
  const dataEntryOffset = IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const fixture = createResourceDirectoryFixture(dataEntryOffset + IMAGE_RESOURCE_DATA_ENTRY_SIZE);
  fixture.writeDirectory(0, 0, 1);
  // Microsoft PE/COFF specification, "The .rsrc Section":
  // the first table lists top-level Type nodes, and its entries point to second-level tables.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  fixture.writeDirectoryEntry(IMAGE_RESOURCE_DIRECTORY_SIZE, 3, dataEntryOffset); // RT_ICON
  fixture.writeDataEntry(dataEntryOffset, 0x00002000, 0x10, 0x000004b0);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [{ typeName: "ICON", kind: "id", leafCount: 0 }]);
  assert.match((tree.issues || []).join(" "), /subdirectory|second-level|type entry/i);
});

void test("buildResourceTree warns when a resource name string offset is not word-aligned", async () => {
  const generatedName = generatedResourceLabel(0);
  const misalignedNameStringOffset =
    IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE + 1;
  const fixture = createResourceDirectoryFixture(misalignedNameStringOffset + 4);
  fixture.writeDirectory(0, 1, 0);
  // Microsoft PE/COFF specification, "Resource Directory String":
  // these Unicode strings are word-aligned.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-string
  fixture.writeDirectoryEntry(IMAGE_RESOURCE_DIRECTORY_SIZE, resourceNameString(misalignedNameStringOffset), 0);
  fixture.writeUtf16Label(misalignedNameStringOffset, generatedName);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [{ typeName: generatedName, kind: "name", leafCount: 0 }]);
  assert.match((tree.issues || []).join(" "), /word-aligned|aligned/i);
});

void test("keeps numeric RT_DIALOG separate from a custom type named DIALOG", async () => {
  const fixture = createResourceDirectoryFixture(0x100);
  fixture.writeDirectory(0, 1, 1);
  fixture.writeDirectoryEntry(0x10, resourceNameString(0xd0), resourceSubdirectory(0x20));
  // RT_DIALOG is ordinal 5 in the Windows SDK WinUser.h.
  fixture.writeDirectoryEntry(0x18, 5, resourceSubdirectory(0x38));
  fixture.writeDirectory(0x20, 0, 1);
  fixture.writeDirectoryEntry(0x30, 1, resourceSubdirectory(0x50));
  fixture.writeDirectory(0x38, 0, 1);
  fixture.writeDirectoryEntry(0x48, 1, resourceSubdirectory(0x68));
  fixture.writeDirectory(0x50, 0, 1);
  fixture.writeDirectoryEntry(0x60, 0x409, 0x80);
  fixture.writeDirectory(0x68, 0, 1);
  fixture.writeDirectoryEntry(0x78, 0x409, 0x90);
  fixture.writeUtf16Label(0xd0, "DIALOG");
  const text = new TextEncoder().encode("Custom text");
  fixture.bytes.set(text, 0xe0);
  fixture.writeDataEntry(0x80, 0xe1, text.length, 0);
  fixture.writeDataEntry(0x90, 0xf1, 4, 0);

  const parsed = await parseResources(new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length), rva => rva - FIXTURE_RESOURCE_RVA);

  assert.deepEqual(parsed?.detail.map(group => group.typeKey), ["DIALOG", 5]);
  assert.deepEqual(parsed?.detail.map(group => group.entries.length), [1, 1]);
  assert.equal(parsed?.detail[0]?.entries[0]?.langs[0]?.previewIssues, undefined);
  assert.match(parsed?.detail[1]?.entries[0]?.langs[0]?.previewIssues?.join(" ") ?? "", /DIALOG/);
});
