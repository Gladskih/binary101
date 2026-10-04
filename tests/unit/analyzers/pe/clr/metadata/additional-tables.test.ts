"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildClrMetadataTables } from "../../../../../../analyzers/pe/clr/metadata-model.js";
import { ClrHeapReaders } from "../../../../../../analyzers/pe/clr/metadata-heaps.js";
import type { ClrMetadataRow, ClrParsedTableStream } from "../../../../../../analyzers/pe/clr/metadata-table-reader.js";
import { tableSchemaById } from "../../../../../../analyzers/pe/clr/metadata-schema.js";
import { createAdditionalTables } from "../../../../../../analyzers/pe/clr/metadata-additional-tables.js";

const streamWithRows = (tableId: number, rows: ClrMetadataRow[]): ClrParsedTableStream => ({
  streamName: "#~", majorVersion: 2, minorVersion: 0, heapSizes: 0, largestRidLog2: 1,
  validMask: 0n, sortedMask: 0n, heapIndexSizes: { string: 2, guid: 2, blob: 2 }, rowCounts: [],
  tables: new Map([[tableId, { schema: tableSchemaById(tableId)!, rowSize: 0, rows }]])
});

const heaps = (blob: number[], issues: string[] = []): ClrHeapReaders => new ClrHeapReaders({
  strings: new TextEncoder().encode("\0Item\0"), guid: null,
  blob: Uint8Array.from(blob), userString: null
}, issues);

void test("exposes property names, flags and decoded signatures", () => {
  // ECMA-335 II.22.34 Property (0x17), II.23.2.5 PROPERTY=0x08, HASTHIS=0x20.
  const metadata = buildClrMetadataTables(streamWithRows(0x17, [{ Flags: 0, Name: 1, Type: 1 }]),
    heaps([0, 3, 0x28, 0, 8]));
  assert.deepEqual(metadata.additionalTables, [{ tableId: 0x17, rows: [{
    Flags: 0, Name: "Item", Type: { callingConvention: 0x28, parameterCount: 0,
      returnType: "i4", parameterTypes: [] }
  }] }]);
});

void test("exposes type specifications", () => {
  // ECMA-335 II.22.39 TypeSpec (0x1b), II.23.2.14: a single Type signature.
  const metadata = buildClrMetadataTables(streamWithRows(0x1b, [{ Signature: 1 }]), heaps([0, 2, 0x1d, 8]));
  assert.deepEqual(metadata.additionalTables?.[0]?.rows, [{ Signature: { type: "i4[]" } }]);
});

void test("exposes generic method instantiations and standalone local signatures", () => {
  // ECMA-335 II.22.29 MethodSpec (0x2b), II.23.2.15 GENERICINST=0x0a.
  const method = { table: "MethodDef", tableId: 6, row: 1, raw: 2, valid: true };
  const metadata = buildClrMetadataTables(streamWithRows(0x2b, [{ Method: method, Instantiation: 1 }]),
    heaps([0, 3, 0x0a, 1, 8]));
  assert.deepEqual(metadata.additionalTables?.[0]?.rows, [{ Method: method, Instantiation: { types: ["i4"] } }]);
  // ECMA-335 II.22.36 StandAloneSig (0x11), II.23.2.6 LOCAL_SIG=0x07, PINNED=0x45.
  const locals = buildClrMetadataTables(streamWithRows(0x11, [{ Signature: 1 }]), heaps([0, 4, 7, 1, 0x45, 8]));
  assert.deepEqual(locals.additionalTables?.[0]?.rows, [{ Signature: { types: ["i4 pinned"] } }]);
});

void test("retains uninterpreted marshal blobs and missing-heap warnings", () => {
  // ECMA-335 II.22.17 FieldMarshal (0x0d) NativeType is a blob.
  const parent = { table: "Field", tableId: 4, row: 1, raw: 2, valid: true };
  const issues: string[] = [];
  const metadata = buildClrMetadataTables(streamWithRows(0x0d, [{ Parent: parent, NativeType: 1 }]),
    heaps([0, 2, 0x2a, 8], issues));
  assert.deepEqual(metadata.additionalTables?.[0]?.rows, [{ Parent: parent, NativeType: [0x2a, 8] }]);
  assert.deepEqual(issues, []);
});

void test("retains missing blobs and invalid references with warnings", () => {
  const issues: string[] = [];
  const readers = heaps([0], issues);
  assert.deepEqual(createAdditionalTables(streamWithRows(0x1b, [{ Signature: 99 }]), readers),
    [{ tableId: 0x1b, rows: [{ Signature: null }] }]);
  assert.match(issues[0] ?? "", /TypeSpec row 1\.Signature.*outside the heap/);
});

void test("does not duplicate modeled tables and supplies missing scalar cells", () => {
  assert.deepEqual(createAdditionalTables(streamWithRows(0, []), heaps([0])), []);
  // ECMA-335 II.22.18 FieldLayout (0x10) includes a byte offset and Field RID.
  assert.deepEqual(createAdditionalTables(streamWithRows(0x10, [{}]), heaps([0])),
    [{ tableId: 0x10, rows: [{ Offset: 0, Field: 0 }] }]);
});

// ECMA-335 II.22: blob columns in StandAloneSig, Property, TypeSpec, MethodSpec and FieldMarshal.
for (const [tableId, column] of [
  [0x11, "Signature"], [0x17, "Type"], [0x1b, "Signature"], [0x2b, "Instantiation"], [0x0d, "NativeType"]
] as const) {
  void test(`reports an absent ${column} blob in table ${tableId}`, () => {
    const issues: string[] = [];
    const tables = createAdditionalTables(streamWithRows(tableId, [{ [column]: 99 }]), heaps([0], issues));
    assert.equal(tables.length, 1);
    assert.equal(tables[0]?.rows[0]?.[column], null);
    assert.match(issues[0] ?? "", /row 1.*outside the heap/);
  });
}
