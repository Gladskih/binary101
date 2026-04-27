"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { ClrHeapReaders, readCompressedUInt } from "../../analyzers/pe/clr/metadata-heaps.js";

const encoder = new TextEncoder();

const makeReaders = (strings: Uint8Array | null, guid: Uint8Array | null, blob: Uint8Array | null) => {
  const issues: string[] = [];
  const readers = new ClrHeapReaders({ strings, guid, blob, userString: null }, issues);
  return { readers, issues };
};

void test("readCompressedUInt decodes ECMA-335 PackedLen forms and rejects malformed tags", () => {
  assert.deepStrictEqual(readCompressedUInt(Uint8Array.of(0x7f), 0), { value: 0x7f, size: 1 });
  assert.deepStrictEqual(readCompressedUInt(Uint8Array.of(0x81, 0x23), 0), { value: 0x123, size: 2 });
  assert.deepStrictEqual(
    readCompressedUInt(Uint8Array.of(0xc0, 0x00, 0x12, 0x34), 0),
    { value: 0x1234, size: 4 }
  );
  assert.strictEqual(readCompressedUInt(Uint8Array.of(0xe0), 0), null);
  assert.strictEqual(readCompressedUInt(Uint8Array.of(0x81), 0), null);
});

void test("ClrHeapReaders reads strings, GUIDs, and blobs with bounds warnings", () => {
  const strings = Uint8Array.of(0, ...encoder.encode("Name"), 0);
  const guid = Uint8Array.of(
    0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  );
  const blob = Uint8Array.of(0, 3, 0xde, 0xad, 0xbe);
  const { readers, issues } = makeReaders(strings, guid, blob);

  assert.strictEqual(readers.getString(1, "Module.Name"), "Name");
  assert.strictEqual(readers.getGuid(1, "Module.Mvid"), "00112233-4455-6677-8899-aabbccddeeff");
  assert.deepStrictEqual([...(readers.getBlob(1, "Method.Signature") ?? [])], [0xde, 0xad, 0xbe]);
  assert.deepStrictEqual(issues, []);
});

void test("ClrHeapReaders reports missing, unterminated, and out-of-range heap entries", () => {
  const { readers, issues } = makeReaders(Uint8Array.of(0, 0x41, 0x42), null, Uint8Array.of(0, 4, 1));

  assert.strictEqual(readers.getString(1, "Type.Name"), "AB");
  assert.strictEqual(readers.getString(12, "Type.Namespace"), null);
  assert.strictEqual(readers.getGuid(1, "Module.Mvid"), null);
  assert.strictEqual(readers.getBlob(1, "CustomAttribute.Value"), null);
  assert.ok(issues.some(issue => /not null-terminated/i.test(issue)));
  assert.ok(issues.some(issue => /outside the heap/i.test(issue)));
  assert.ok(issues.some(issue => /#GUID, but the heap is absent/i.test(issue)));
  assert.ok(issues.some(issue => /extends past the heap/i.test(issue)));
});
