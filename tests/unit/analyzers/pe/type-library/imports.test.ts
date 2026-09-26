import assert from "node:assert/strict";
import { test } from "node:test";
import { readImports, readImportedTypes } from "../../../../../analyzers/pe/type-library/imports.js";
import { createLibraryReader } from "../../../../fixtures/type-library.js";

void test("imports decode packed filename lengths, GUID, LCID and version", () => {
  const reader = createLibraryReader("ImpFiles", 16);
  reader.guids.set(0, "library-guid");
  reader.view.setUint32(4, 1033, true);
  reader.view.setUint32(8, 0x20001, true);
  reader.view.setUint16(12, 1 << 2, true);
  reader.data[14] = 65;
  assert.deepEqual(readImports(reader), [
    { offset: 0, name: "A", guid: "library-guid", lcid: 1033, version: 0x20001 }
  ]);
  assert.deepEqual(readImportedTypes(reader), []);
});

void test("missing import segments are empty", () => {
  assert.deepEqual(readImports(createLibraryReader("missing")), []);
});

for (const size of [1, 13, 14]) {
  void test(`imports reject truncated headers or alignment (${size})`, () => {
    const reader = createLibraryReader("ImpFiles", size);
    assert.deepEqual(readImports(reader), []);
    assert.ok(reader.issues.length);
  });
}

void test("imports reject filenames exceeding the segment", () => {
  const reader = createLibraryReader("ImpFiles", 16);
  reader.view.setUint16(12, 0xfffc, true);
  assert.deepEqual(readImports(reader), []);
  assert.ok(reader.issues.length);
});

void test("imported types can identify types by index rather than GUID", () => {
  const reader = createLibraryReader("ImpInfo", 13);
  reader.view.setUint32(4, 32, true);
  reader.view.setInt32(8, 7, true);
  assert.deepEqual(readImportedTypes(reader), [
    { offset: 0, flags: 0, libraryOffset: 32, identifier: 7 }
  ]);
  assert.match(reader.issues.join(), /truncated/);
});
