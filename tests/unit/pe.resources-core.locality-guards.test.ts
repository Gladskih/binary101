"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildResourceTree } from "../../analyzers/pe/resources-core.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  createResourceDirectoryFixture,
  IMAGE_RESOURCE_DATA_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_SIZE,
  resourceSubdirectory
} from "../helpers/pe-resource-fixture.js";

const FIXTURE_RESOURCE_RVA = 1;

const buildFixtureResourceDirectory = (size: number) => [{ name: "RESOURCE", rva: FIXTURE_RESOURCE_RVA, size }];

function ignoreCoverage(_label: string, _start: number, _size: number): void {}

const createLocalityFixture = (fileSize = 0x100) => {
  const fixture = createResourceDirectoryFixture(fileSize);
  let nextOffset = 0;
  let nextDataRva = FIXTURE_RESOURCE_RVA + 1;
  const allocateDirectoryTable = (namedCount: number, idCount: number) => {
    const offset = nextOffset;
    const entryCount = namedCount + idCount;
    fixture.writeDirectory(offset, namedCount, idCount);
    nextOffset += IMAGE_RESOURCE_DIRECTORY_SIZE + entryCount * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
    return {
      offset,
      entryOffset: (index: number): number =>
        offset + IMAGE_RESOURCE_DIRECTORY_SIZE + index * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
    };
  };
  const allocateDataEntry = (
    dataRva = nextDataRva,
    size = Uint32Array.BYTES_PER_ELEMENT
  ): number => {
    const offset = nextOffset;
    fixture.writeDataEntry(offset, dataRva, size, 0);
    nextOffset += IMAGE_RESOURCE_DATA_ENTRY_SIZE;
    nextDataRva = dataRva + size;
    return offset;
  };
  return { ...fixture, allocateDirectoryTable, allocateDataEntry };
};

void test("buildResourceTree exposes IMAGE_RESOURCE_DIRECTORY headers", async () => {
  const fixture = createLocalityFixture();
  const rootDirectory = fixture.allocateDirectoryTable(0, 1);
  const nameDirectory = fixture.allocateDirectoryTable(0, 1);
  const languageDirectory = fixture.allocateDirectoryTable(0, 1);
  const dataEntryOffset = fixture.allocateDataEntry();
  fixture.writeDirectoryEntry(rootDirectory.entryOffset(0), 3, resourceSubdirectory(nameDirectory.offset));
  fixture.writeDirectoryEntry(nameDirectory.entryOffset(0), 1, resourceSubdirectory(languageDirectory.offset));
  fixture.writeDirectoryEntry(languageDirectory.entryOffset(0), 1033, dataEntryOffset);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    value => value - FIXTURE_RESOURCE_RVA,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.equal(tree.directories?.length, 3);
  assert.deepEqual(tree.directories?.map(directory => directory.offset), [
    rootDirectory.offset,
    nameDirectory.offset,
    languageDirectory.offset
  ]);
});

void test("buildResourceTree warns when a subdirectory target points into the Resource Data entry area", async () => {
  const fixture = createLocalityFixture();
  const rootDirectory = fixture.allocateDirectoryTable(0, 2);
  const validNameDirectory = fixture.allocateDirectoryTable(0, 1);
  const validLanguageDirectory = fixture.allocateDirectoryTable(0, 1);
  const dataEntryOffset = fixture.allocateDataEntry();
  // Resource Directory Entries that mark DataIsDirectory=1 point to another
  // Resource Directory Table, not to the Resource Data Description area.
  // Source: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
  fixture.writeDirectoryEntry(
    rootDirectory.entryOffset(0),
    3,
    resourceSubdirectory(validNameDirectory.offset)
  );
  fixture.writeDirectoryEntry(rootDirectory.entryOffset(1), 4, resourceSubdirectory(dataEntryOffset));
  fixture.writeDirectoryEntry(
    validNameDirectory.entryOffset(0),
    1,
    resourceSubdirectory(validLanguageDirectory.offset)
  );
  fixture.writeDirectoryEntry(validLanguageDirectory.entryOffset(0), 1033, dataEntryOffset);

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    value => value - FIXTURE_RESOURCE_RVA,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.match((tree.issues || []).join(" "), /subdirectory.*outside the Resource Directory area/i);
});

void test("buildResourceTree warns when a resource payload RVA lies outside the declared .rsrc span", async () => {
  const fixture = createLocalityFixture();
  const rootDirectory = fixture.allocateDirectoryTable(0, 1);
  const nameDirectory = fixture.allocateDirectoryTable(0, 1);
  const languageDirectory = fixture.allocateDirectoryTable(0, 1);
  const dataEntryOffset = fixture.allocateDataEntry(FIXTURE_RESOURCE_RVA + fixture.bytes.length + 0x20);
  fixture.writeDirectoryEntry(rootDirectory.entryOffset(0), 3, resourceSubdirectory(nameDirectory.offset));
  fixture.writeDirectoryEntry(nameDirectory.entryOffset(0), 1, resourceSubdirectory(languageDirectory.offset));
  fixture.writeDirectoryEntry(languageDirectory.entryOffset(0), 1033, dataEntryOffset);
  const fileBytes = new Uint8Array(fixture.bytes.length + 0x80);
  fileBytes.set(fixture.bytes);

  const tree = await buildResourceTree(
    new MockFile(fileBytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    value => value - FIXTURE_RESOURCE_RVA,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.match((tree.issues || []).join(" "), /outside the declared \.rsrc RVA span/i);
});

void test("buildResourceTree warns when a resource payload maps outside the .rsrc file span", async () => {
  const fixture = createLocalityFixture();
  const rootDirectory = fixture.allocateDirectoryTable(0, 1);
  const nameDirectory = fixture.allocateDirectoryTable(0, 1);
  const languageDirectory = fixture.allocateDirectoryTable(0, 1);
  const dataEntryOffset = fixture.allocateDataEntry(FIXTURE_RESOURCE_RVA + 0x90);
  fixture.writeDirectoryEntry(rootDirectory.entryOffset(0), 3, resourceSubdirectory(nameDirectory.offset));
  fixture.writeDirectoryEntry(nameDirectory.entryOffset(0), 1, resourceSubdirectory(languageDirectory.offset));
  fixture.writeDirectoryEntry(languageDirectory.entryOffset(0), 1033, dataEntryOffset);
  const fileBytes = new Uint8Array(fixture.bytes.length + 0x100);
  fileBytes.set(fixture.bytes);

  const tree = await buildResourceTree(
    new MockFile(fileBytes),
    buildFixtureResourceDirectory(fixture.bytes.length),
    value => value === FIXTURE_RESOURCE_RVA + 0x90
      ? fixture.bytes.length + 0x20
      : value - FIXTURE_RESOURCE_RVA,
    ignoreCoverage
  );
  assert.ok(tree);

  assert.match((tree.issues || []).join(" "), /maps outside the \.rsrc file span/i);
});
