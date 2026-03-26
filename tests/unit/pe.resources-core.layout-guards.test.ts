"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildResourceTree } from "../../analyzers/pe/resources-core.js";
import { MockFile } from "../helpers/mock-file.js";
import {
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

function ignoreCoverage(_label: string, _start: number, _size: number): void {}

void test("buildResourceTree warns when a resource string appears before the last directory entry", async () => {
  const generatedName = generatedResourceLabel(0);
  const fixture = createResourceDirectoryFixture(0xb0);
  fixture.writeDirectory(0, 1, 0);
  // Microsoft PE/COFF specification, "Resource Directory String":
  // resource strings are stored after the last Resource Directory entry.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-string
  fixture.writeDirectoryEntry(
    IMAGE_RESOURCE_DIRECTORY_SIZE,
    resourceNameString(0x50),
    resourceSubdirectory(0x20)
  );
  fixture.writeDirectory(0x20, 0, 1);
  fixture.writeDirectoryEntry(0x30, 1, resourceSubdirectory(0x80));
  fixture.writeDirectory(0x80, 0, 1);
  fixture.writeDirectoryEntry(0x90, 0x00000409, 0x000000a0);
  fixture.writeDataEntry(0xa0, 0x00002000, 0x10, 0x000004b0);
  fixture.writeUtf16Label(0x50, generatedName);

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
  const fixture = createResourceDirectoryFixture(0x80);
  fixture.writeDirectory(0, 0, 1);
  fixture.writeDirectoryEntry(0x10, 3, resourceSubdirectory(0x20));
  fixture.writeDirectory(0x20, 1, 0);
  // Microsoft PE/COFF specification, "Resource Directory String":
  // resource strings are stored before the first Resource Data entry.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-string
  fixture.writeDirectoryEntry(0x30, resourceNameString(0x70), resourceSubdirectory(0x40));
  fixture.writeDirectory(0x40, 0, 1);
  fixture.writeDirectoryEntry(0x50, 0x00000409, 0x00000060);
  fixture.writeDataEntry(0x60, 0x00002000, 0x10, 0x000004b0);
  fixture.writeUtf16Label(0x70, generatedName);

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

void test("buildResourceTree warns when a resource data payload RVA cannot be mapped", async () => {
  const fixture = createResourceDirectoryFixture(0x70);
  fixture.writeDirectory(0, 0, 1);
  fixture.writeDirectoryEntry(0x10, 3, resourceSubdirectory(0x20));
  fixture.writeDirectory(0x20, 0, 1);
  fixture.writeDirectoryEntry(0x30, 1, resourceSubdirectory(0x40));
  fixture.writeDirectory(0x40, 0, 1);
  // Microsoft PE/COFF specification, "Resource Data Entry":
  // Data RVA points at the actual unit of resource data in the Resource Data area.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-data-entry
  fixture.writeDirectoryEntry(0x50, 0x00000409, 0x00000060);
  fixture.writeDataEntry(0x60, 0x00002000, 0x10, 0x000004b0);

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
  const fixture = createResourceDirectoryFixture(0xc0);
  fixture.writeDirectory(0, 0, 1);
  fixture.writeDirectoryEntry(0x10, 3, resourceSubdirectory(0x20));
  // Inference from the Microsoft PE/COFF .rsrc tree model:
  // sibling entries at one directory level are keyed by Type, Name, or Language,
  // so duplicate sibling names represent an ambiguous resource lookup.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  fixture.writeDirectory(0x20, 2, 0);
  fixture.writeDirectoryEntry(0x30, resourceNameString(0x80), resourceSubdirectory(0x40));
  fixture.writeDirectoryEntry(0x38, resourceNameString(0x84), resourceSubdirectory(0x60));
  fixture.writeDirectory(0x40, 0, 1);
  fixture.writeDirectoryEntry(0x50, 0x00000409, 0x000000a0);
  fixture.writeDirectory(0x60, 0, 1);
  fixture.writeDirectoryEntry(0x70, 0x0000040a, 0x000000b0);
  fixture.writeUtf16Label(0x80, duplicateName);
  fixture.writeUtf16Label(0x84, duplicateName);
  fixture.writeDataEntry(0xa0, 0x00002000, 0x10, 0x000004b0);
  fixture.writeDataEntry(0xb0, 0x00002010, 0x10, 0x000004b0);

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
  const fixture = createResourceDirectoryFixture(0x90);
  fixture.writeDirectory(0, 0, 1);
  fixture.writeDirectoryEntry(0x10, 3, resourceSubdirectory(0x20));
  // Inference from the Microsoft PE/COFF .rsrc tree model:
  // sibling Language entries at one level must uniquely identify the resource variant.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  fixture.writeDirectory(0x20, 0, 1);
  fixture.writeDirectoryEntry(0x30, 1, resourceSubdirectory(0x40));
  fixture.writeDirectory(0x40, 0, 2);
  fixture.writeDirectoryEntry(0x50, 0x00000409, 0x00000070);
  fixture.writeDirectoryEntry(
    0x50 + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
    0x00000409,
    0x00000080
  );
  fixture.writeDataEntry(0x70, 0x00002000, 0x10, 0x000004b0);
  fixture.writeDataEntry(0x80, 0x00002010, 0x10, 0x000004b0);

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
