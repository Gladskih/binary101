"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  ResourceDirectoryEntry,
  ResourceDirectoryLabelReadResult
} from "../../../../../../analyzers/pe/resources/directory-rules.js";
import {
  validateResourceDirectoryDuplicates,
  validateResourceDirectoryEntryKinds,
  validateResourceDirectoryIdSort,
  validateResourceDirectoryNameSort
} from "../../../../../../analyzers/pe/resources/directory-rules.js";

const idEntry = (id: number): ResourceDirectoryEntry => ({
  nameIsString: false,
  subdir: false,
  nameOrId: id,
  target: 0
});

const nameEntry = (rel: number, invalidNameOffset = false): ResourceDirectoryEntry => ({
  nameIsString: true,
  subdir: false,
  nameOrId: rel,
  target: 0,
  ...(invalidNameOffset ? { invalidNameOffset } : {})
});

const labelReader = (
  labels: Record<number, string>
): ((rel: number) => Promise<ResourceDirectoryLabelReadResult>) => async rel => ({
  text: labels[rel] ?? "",
  issues: [`label:${rel}`],
  resourceStringRanges: [{ start: rel, end: rel + 4 }]
});

void test("directory entry kind validation enforces named entries before ID entries", () => {
  assert.deepStrictEqual(validateResourceDirectoryEntryKinds(0x20, 1, [
    nameEntry(0x80),
    idEntry(1),
    idEntry(2)
  ]), []);
  assert.deepStrictEqual(validateResourceDirectoryEntryKinds(0x20, 2, [
    idEntry(1),
    nameEntry(0x80)
  ]), [
    "Resource directory at 0x20 has ID entries inside the name-entry range; "
      + "named entries must appear before ID entries."
  ]);
  assert.deepStrictEqual(validateResourceDirectoryEntryKinds(0x20, 1, [
    nameEntry(0x80),
    nameEntry(0x84)
  ]), [
    "Resource directory at 0x20 has named entries after ID entries; "
      + "named entries must appear before ID entries."
  ]);
});

void test("directory ID sort validation reports descending IDs without rejecting equal IDs", () => {
  assert.deepStrictEqual(validateResourceDirectoryIdSort(0x20, 1, [
    nameEntry(0x80),
    idEntry(1),
    idEntry(1)
  ]), []);
  assert.deepStrictEqual(validateResourceDirectoryIdSort(0x20, 1, [
    nameEntry(0x80),
    idEntry(2),
    idEntry(1)
  ]), [
    "Resource directory at 0x20 has ID entries that are not sorted in ascending order."
  ]);
  assert.deepStrictEqual(validateResourceDirectoryIdSort(0x20, 1, [
    idEntry(9),
    idEntry(1)
  ]), []);
});

void test("directory name sort validation reports descending labels and preserves label facts", async () => {
  const result = await validateResourceDirectoryNameSort(0x20, 2, [
    nameEntry(0x80),
    nameEntry(0x84)
  ], labelReader({ 0x80: "Zulu", 0x84: "Alpha" }));

  assert.deepStrictEqual(result.issues, [
    "label:128",
    "label:132",
    "Resource directory at 0x20 has named entries that are not sorted in ascending order."
  ]);
  assert.deepStrictEqual(result.resourceStringRanges, [
    { start: 0x80, end: 0x84 },
    { start: 0x84, end: 0x88 }
  ]);
});

void test("directory name sort validation accepts equal adjacent labels", async () => {
  const result = await validateResourceDirectoryNameSort(0x20, 2, [
    nameEntry(0x80),
    nameEntry(0x84)
  ], labelReader({ 0x80: "Same", 0x84: "Same" }));

  assert.deepStrictEqual(result.issues, ["label:128", "label:132"]);
});

void test("directory name sort validation only reads the declared named-entry range", async () => {
  const result = await validateResourceDirectoryNameSort(0x20, 1, [
    nameEntry(0x80),
    nameEntry(0x84)
  ], labelReader({ 0x80: "Beta", 0x84: "Alpha" }));

  assert.deepStrictEqual(result.issues, ["label:128"]);
  assert.deepStrictEqual(result.resourceStringRanges, [{ start: 0x80, end: 0x84 }]);
});

void test("directory duplicate validation reports duplicate names and IDs", async () => {
  const duplicateName = await validateResourceDirectoryDuplicates(0x20, [
    nameEntry(0x80),
    nameEntry(0x84)
  ], labelReader({ 0x80: "same", 0x84: "same" }));
  const duplicateId = await validateResourceDirectoryDuplicates(0x20, [
    idEntry(7),
    idEntry(7)
  ], labelReader({}));

  assert.deepStrictEqual(duplicateName.issues, [
    "label:128",
    "label:132",
    "Resource directory at 0x20 has duplicate named entries for \"same\"."
  ]);
  assert.deepStrictEqual(duplicateName.resourceStringRanges, [
    { start: 0x80, end: 0x84 },
    { start: 0x84, end: 0x88 }
  ]);
  assert.deepStrictEqual(duplicateId.issues, [
    "Resource directory at 0x20 has duplicate ID entries for 0x7."
  ]);
});

void test("directory duplicate validation accepts unique names and IDs", async () => {
  const result = await validateResourceDirectoryDuplicates(0x20, [
    nameEntry(0x80),
    idEntry(7),
    nameEntry(0x84),
    idEntry(8)
  ], labelReader({ 0x80: "Alpha", 0x84: "Beta" }));

  assert.deepStrictEqual(result.issues, ["label:128", "label:132"]);
});

void test("directory name validation skips invalid name offsets", async () => {
  const readOffsets: number[] = [];
  const result = await validateResourceDirectoryNameSort(0x20, 2, [
    nameEntry(0x80, true),
    nameEntry(0x84)
  ], async rel => {
    readOffsets.push(rel);
    return { text: "OnlyValid", issues: [], resourceStringRanges: [] };
  });

  assert.deepStrictEqual(readOffsets, [0x84]);
  assert.deepStrictEqual(result, { issues: [], resourceStringRanges: [] });
});

void test("directory duplicate validation skips invalid named offsets", async () => {
  const readOffsets: number[] = [];
  const result = await validateResourceDirectoryDuplicates(0x20, [
    nameEntry(0x80, true),
    nameEntry(0x84)
  ], async rel => {
    readOffsets.push(rel);
    return { text: "same", issues: [], resourceStringRanges: [] };
  });

  assert.deepStrictEqual(readOffsets, [0x84]);
  assert.deepStrictEqual(result, { issues: [], resourceStringRanges: [] });
});
