"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildClrMetadataTables } from "../../../../../../analyzers/pe/clr/metadata-model.js";
import { ClrHeapReaders } from "../../../../../../analyzers/pe/clr/metadata-heaps.js";
import { tableSchemaById } from "../../../../../../analyzers/pe/clr/metadata-schema.js";
import type {
  ClrMetadataRow, ClrParsedTable, ClrParsedTableStream
} from "../../../../../../analyzers/pe/clr/metadata-table-reader.js";

const index = (tableId: number, row: number) => ({ table: "fixture", tableId, row, raw: 0, valid: true });
const metadataTable = (tableId: number, rows: ClrMetadataRow[]): [number, ClrParsedTable] =>
  [tableId, { schema: tableSchemaById(tableId)!, rowSize: 0, rows }];

const enumTables = (): ClrParsedTableStream => ({
  streamName: "#-", majorVersion: 2, minorVersion: 0, heapSizes: 0, largestRidLog2: 0,
  validMask: 0n, sortedMask: 0n, heapIndexSizes: { string: 2, guid: 2, blob: 2 }, rowCounts: [],
  // ECMA-335 II.22: independent table ids for TypeRef, TypeDef, FieldPtr, Field, MethodDef and CustomAttribute.
  tables: new Map([
    metadataTable(1, [{ ResolutionScope: index(35, 1), TypeName: 1, TypeNamespace: 6 }]),
    metadataTable(2, [{ TypeName: 13, TypeNamespace: 0, Flags: 0, Extends: index(1, 1),
      FieldList: index(3, 1), MethodList: index(6, 1) }]),
    metadataTable(3, [{ Field: index(4, 1) }]),
    metadataTable(4, [{ Name: 18, Flags: 0, Signature: 1 }]),
    metadataTable(6, [{ Name: 26, Flags: 0, ImplFlags: 0, RVA: 0, Signature: 4, ParamList: index(8, 1) }]),
    metadataTable(12, [{ Parent: index(2, 1), Type: index(6, 1), Value: 10 }])
  ])
});

const enumHeaps = (): ClrHeapReaders => new ClrHeapReaders({
  strings: new TextEncoder().encode("\0Enum\0System\0Mode\0value__\0.ctor\0"), guid: null, userString: null,
  // FIELD I1; instance constructor(void, valuetype TypeDef#1); attribute(-1), NumNamed=0.
  blob: Uint8Array.of(0, 2, 6, 4, 5, 0x20, 1, 1, 0x11, 4, 5, 1, 0, 0xff, 0, 0)
}, []);

void test("does not infer enum width from a FieldList that indexes FieldPtr", () => {
  const tables = buildClrMetadataTables(enumTables(), enumHeaps());
  assert.match(tables.customAttributes[0]?.issues?.[0] ?? "", /underlying type is unresolved/);
  assert.equal(tables.customAttributes[0]?.fixedArguments[0]?.value, null);
});

void test("resolves enum width when FieldList indexes Field directly", () => {
  const parsed = enumTables();
  parsed.tables.delete(3);
  parsed.tables.get(2)!.rows[0]!["FieldList"] = index(4, 1);
  const tables = buildClrMetadataTables(parsed, enumHeaps());
  assert.equal(tables.customAttributes[0]?.fixedArguments[0]?.value, -1);
  assert.equal(tables.customAttributes[0]?.issues, undefined);
});
