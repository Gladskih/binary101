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
  resourceNameString,
  resourceSubdirectory
} from "../helpers/pe-resource-fixture.js";

// `buildResourceTree()` ignores a `RESOURCE` directory whose RVA is zero.
const FIXTURE_RESOURCE_RVA = 1;
// Microsoft Resource Types: `RT_ICON` = 3.
// https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types
const ICON_RESOURCE_TYPE_ID = 3;

const generatedResourceLabel = (index: number): string => index.toString(36);

const buildFixtureResourceDirectory = (size: number) => [
  { name: "RESOURCE", rva: FIXTURE_RESOURCE_RVA, size }
];

function mapFixtureRvaToStart(_value: number): number {
  return 0;
}

function ignoreCoverage(_label: string, _start: number, _size: number): void {}

// 512 bytes is enough for the synthetic `.rsrc` trees in this file because offsets are
// allocated sequentially and the fixtures only model metadata, not large raw payloads.
const createLayoutGuardFixture = (fileSize = 0x200) => {
  const fixture = createResourceDirectoryFixture(fileSize);
  let nextOffset = 0;
  let nextDataRva = FIXTURE_RESOURCE_RVA + 1;

  const allocateDirectoryTable = (namedCount: number, idCount: number) => {
    const offset = nextOffset;
    const entryCount = namedCount + idCount;
    const entryOffsets = Array.from(
      { length: entryCount },
      (_unused, index) =>
        offset + IMAGE_RESOURCE_DIRECTORY_SIZE + index * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
    );
    fixture.writeDirectory(offset, namedCount, idCount);
    nextOffset += IMAGE_RESOURCE_DIRECTORY_SIZE + entryCount * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
    return {
      offset,
      entryOffset: (index: number): number => {
        const entryOffset = entryOffsets[index];
        if (entryOffset == null) {
          throw new Error(`Missing resource directory entry at index ${index}.`);
        }
        return entryOffset;
      }
    };
  };

  const allocateDataEntry = (size = Uint32Array.BYTES_PER_ELEMENT) => {
    const offset = nextOffset;
    fixture.writeDataEntry(offset, nextDataRva, size, 0);
    nextDataRva += size;
    nextOffset += IMAGE_RESOURCE_DATA_ENTRY_SIZE;
    return offset;
  };

  const allocateUtf16Label = (text: string, declaredLength = text.length) => {
    const offset = nextOffset;
    fixture.writeUtf16Label(offset, text, declaredLength);
    nextOffset += Uint16Array.BYTES_PER_ELEMENT + text.length * Uint16Array.BYTES_PER_ELEMENT;
    return offset;
  };

  return { ...fixture, allocateDirectoryTable, allocateDataEntry, allocateUtf16Label };
};

void test("buildResourceTree warns when a resource string appears before the last directory entry", async () => {
  const generatedName = generatedResourceLabel(0);
  const fixture = createLayoutGuardFixture();
  const rootDirectory = fixture.allocateDirectoryTable(1, 0);
  const nameLabelOffset = fixture.allocateUtf16Label(generatedName);
  const nameDirectory = fixture.allocateDirectoryTable(0, 1);
  const languageDirectory = fixture.allocateDirectoryTable(0, 1);
  const dataEntryOffset = fixture.allocateDataEntry();
  // Microsoft PE/COFF specification, "Resource Directory String":
  // resource strings are stored after the last Resource Directory entry.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-string
  fixture.writeDirectoryEntry(
    rootDirectory.entryOffset(0),
    resourceNameString(nameLabelOffset),
    resourceSubdirectory(nameDirectory.offset)
  );
  fixture.writeDirectoryEntry(nameDirectory.entryOffset(0), 1, resourceSubdirectory(languageDirectory.offset));
  fixture.writeDirectoryEntry(languageDirectory.entryOffset(0), 1, dataEntryOffset);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [{ typeName: generatedName, kind: "name", leafCount: 1 }]);
  assert.match((tree.issues || []).join(" "), /last resource directory entry|string area/i);
});

void test("buildResourceTree warns when a resource data entry appears before the string area ends", async () => {
  const generatedName = generatedResourceLabel(0);
  const fixture = createLayoutGuardFixture();
  const rootDirectory = fixture.allocateDirectoryTable(0, 1);
  const nameDirectory = fixture.allocateDirectoryTable(1, 0);
  const languageDirectory = fixture.allocateDirectoryTable(0, 1);
  const dataEntryOffset = fixture.allocateDataEntry();
  const nameLabelOffset = fixture.allocateUtf16Label(generatedName);
  // Microsoft PE/COFF specification, "Resource Directory String":
  // resource strings are stored before the first Resource Data entry.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-string
  fixture.writeDirectoryEntry(
    rootDirectory.entryOffset(0),
    ICON_RESOURCE_TYPE_ID,
    resourceSubdirectory(nameDirectory.offset)
  );
  fixture.writeDirectoryEntry(
    nameDirectory.entryOffset(0),
    resourceNameString(nameLabelOffset),
    resourceSubdirectory(languageDirectory.offset)
  );
  fixture.writeDirectoryEntry(languageDirectory.entryOffset(0), 1, dataEntryOffset);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [{ typeName: "ICON", kind: "id", leafCount: 1 }]);
  assert.match((tree.issues || []).join(" "), /first resource data entry|string area/i);
});

void test("buildResourceTree summarizes interleaved resource strings and data entries once", async () => {
  const fixture = createLayoutGuardFixture();
  const rootDirectory = fixture.allocateDirectoryTable(0, 1);
  const nameDirectory = fixture.allocateDirectoryTable(2, 0);
  const firstLanguageDirectory = fixture.allocateDirectoryTable(0, 1);
  const secondLanguageDirectory = fixture.allocateDirectoryTable(0, 1);
  const firstDataEntryOffset = fixture.allocateDataEntry();
  const secondDataEntryOffset = fixture.allocateDataEntry();
  const firstNameLabelOffset = fixture.allocateUtf16Label(generatedResourceLabel(0));
  const secondNameLabelOffset = fixture.allocateUtf16Label(generatedResourceLabel(1));
  // Microsoft PE/COFF specification, "Resource Directory String":
  // directory strings are grouped before the Resource Data Description area.
  // When the two areas are interleaved, that is one layout anomaly, not hundreds.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-string
  fixture.writeDirectoryEntry(
    rootDirectory.entryOffset(0),
    ICON_RESOURCE_TYPE_ID,
    resourceSubdirectory(nameDirectory.offset)
  );
  fixture.writeDirectoryEntry(
    nameDirectory.entryOffset(0),
    resourceNameString(firstNameLabelOffset),
    resourceSubdirectory(firstLanguageDirectory.offset)
  );
  fixture.writeDirectoryEntry(
    nameDirectory.entryOffset(1),
    resourceNameString(secondNameLabelOffset),
    resourceSubdirectory(secondLanguageDirectory.offset)
  );
  fixture.writeDirectoryEntry(firstLanguageDirectory.entryOffset(0), 1, firstDataEntryOffset);
  fixture.writeDirectoryEntry(secondLanguageDirectory.entryOffset(0), 2, secondDataEntryOffset);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [{ typeName: "ICON", kind: "id", leafCount: 2 }]);
  assert.equal(tree.issues?.length, 1);
  assert.match(tree.issues?.[0] || "", /interleaved|string area|data entries/i);
});

void test("buildResourceTree warns when a resource data payload RVA cannot be mapped", async () => {
  const fixture = createLayoutGuardFixture();
  const rootDirectory = fixture.allocateDirectoryTable(0, 1);
  const nameDirectory = fixture.allocateDirectoryTable(0, 1);
  const languageDirectory = fixture.allocateDirectoryTable(0, 1);
  const dataEntryOffset = fixture.allocateDataEntry();
  // Microsoft PE/COFF specification, "Resource Data Entry":
  // Data RVA points at the actual unit of resource data in the Resource Data area.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-data-entry
  fixture.writeDirectoryEntry(
    rootDirectory.entryOffset(0),
    ICON_RESOURCE_TYPE_ID,
    resourceSubdirectory(nameDirectory.offset)
  );
  fixture.writeDirectoryEntry(nameDirectory.entryOffset(0), 1, resourceSubdirectory(languageDirectory.offset));
  fixture.writeDirectoryEntry(languageDirectory.entryOffset(0), 1, dataEntryOffset);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    value => value === FIXTURE_RESOURCE_RVA ? 0 : null,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [{ typeName: "ICON", kind: "id", leafCount: 1 }]);
  assert.match((tree.issues || []).join(" "), /data payload|data rva|mapped/i);
});

void test("buildResourceTree warns when sibling resource names are duplicated", async () => {
  const duplicateName = generatedResourceLabel(0);
  const fixture = createLayoutGuardFixture();
  const rootDirectory = fixture.allocateDirectoryTable(0, 1);
  const nameDirectory = fixture.allocateDirectoryTable(2, 0);
  const firstLanguageDirectory = fixture.allocateDirectoryTable(0, 1);
  const secondLanguageDirectory = fixture.allocateDirectoryTable(0, 1);
  const firstDuplicateNameOffset = fixture.allocateUtf16Label(duplicateName);
  const secondDuplicateNameOffset = fixture.allocateUtf16Label(duplicateName);
  const firstDataEntryOffset = fixture.allocateDataEntry();
  const secondDataEntryOffset = fixture.allocateDataEntry();
  // Inference from the Microsoft PE/COFF .rsrc tree model:
  // sibling entries at one directory level are keyed by Type, Name, or Language,
  // so duplicate sibling names represent an ambiguous resource lookup.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  fixture.writeDirectoryEntry(
    rootDirectory.entryOffset(0),
    ICON_RESOURCE_TYPE_ID,
    resourceSubdirectory(nameDirectory.offset)
  );
  fixture.writeDirectoryEntry(
    nameDirectory.entryOffset(0),
    resourceNameString(firstDuplicateNameOffset),
    resourceSubdirectory(firstLanguageDirectory.offset)
  );
  fixture.writeDirectoryEntry(
    nameDirectory.entryOffset(1),
    resourceNameString(secondDuplicateNameOffset),
    resourceSubdirectory(secondLanguageDirectory.offset)
  );
  fixture.writeDirectoryEntry(firstLanguageDirectory.entryOffset(0), 1, firstDataEntryOffset);
  fixture.writeDirectoryEntry(secondLanguageDirectory.entryOffset(0), 2, secondDataEntryOffset);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [{ typeName: "ICON", kind: "id", leafCount: 2 }]);
  assert.match((tree.issues || []).join(" "), /duplicate.*name|same name/i);
});

void test("buildResourceTree warns when sibling language IDs are duplicated", async () => {
  const fixture = createLayoutGuardFixture();
  const rootDirectory = fixture.allocateDirectoryTable(0, 1);
  const nameDirectory = fixture.allocateDirectoryTable(0, 1);
  const languageDirectory = fixture.allocateDirectoryTable(0, 2);
  const firstDataEntryOffset = fixture.allocateDataEntry();
  const secondDataEntryOffset = fixture.allocateDataEntry();
  // Inference from the Microsoft PE/COFF .rsrc tree model:
  // sibling Language entries at one level must uniquely identify the resource variant.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  fixture.writeDirectoryEntry(
    rootDirectory.entryOffset(0),
    ICON_RESOURCE_TYPE_ID,
    resourceSubdirectory(nameDirectory.offset)
  );
  fixture.writeDirectoryEntry(nameDirectory.entryOffset(0), 1, resourceSubdirectory(languageDirectory.offset));
  fixture.writeDirectoryEntry(languageDirectory.entryOffset(0), 1, firstDataEntryOffset);
  fixture.writeDirectoryEntry(languageDirectory.entryOffset(1), 1, secondDataEntryOffset);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    mapFixtureRvaToStart,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [{ typeName: "ICON", kind: "id", leafCount: 2 }]);
  assert.match((tree.issues || []).join(" "), /duplicate.*id|duplicate.*language/i);
});
