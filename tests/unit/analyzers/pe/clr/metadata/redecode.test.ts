"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { attachClrResolutionSession } from "../../../../../../analyzers/pe/clr/metadata-redecode.js";
import { getClrResolutionSession } from "../../../../../../analyzers/pe/clr/metadata-resolution-session.js";
import { ClrHeapReaders } from "../../../../../../analyzers/pe/clr/metadata-heaps.js";
import type { ClrParsedTableStream } from "../../../../../../analyzers/pe/clr/metadata-table-reader.js";
import { clrIndex, clrResolutionFixture } from "../../../../../helpers/clr-resolution-fixture.js";

const rawTables = (): ClrParsedTableStream => ({
  streamName: "#~", majorVersion: 2, minorVersion: 0, heapSizes: 0, largestRidLog2: 0,
  validMask: 0n, sortedMask: 0n, heapIndexSizes: { string: 2, guid: 2, blob: 2 }, rowCounts: [],
  tables: new Map([
    [12, { schema: { id: 12, name: "CustomAttribute", columns: [] }, rowSize: 6,
      rows: [{ Parent: clrIndex(32), Type: clrIndex(6), Value: 1 }] }],
    [14, { schema: { id: 14, name: "DeclSecurity", columns: [] }, rowSize: 6,
      rows: [{ PermissionSet: 7 }] }]
  ])
});

const decodingFixture = () => {
  const tables = clrResolutionFixture();
  tables.typeRefs = [{ row: 1, name: "E", namespace: "", fullName: "E", resolutionScope: clrIndex(35) }];
  tables.methodDefs = [{ row: 1, name: ".ctor", ownerType: "A", rva: 0, implFlags: 0, flags: 0, signatureBlobIndex: 0,
    signature: { callingConvention: 0x20, parameterCount: 1, returnType: "void", parameterTypes: ["valuetype TypeRef#1"] } }];
  tables.additionalTables = [
    { tableId: 11, rows: [] },
    { tableId: 14, rows: [{ PermissionSet: null }] }
  ];
  // ECMA-335 II.23.3 prolog 1, enum byte 254, NumNamed 0; security payload uses compressed NumNamed.
  const security = [0x2e, 1, 1, 65, 8, 1, 0x53, 0x55, 1, 69, 1, 66, 254];
  const heaps = new ClrHeapReaders({ strings: null, guid: null, userString: null,
    blob: Uint8Array.of(0, 5, 1, 0, 254, 0, 0, security.length, ...security) }, []);
  return { tables, heaps, parsed: rawTables() };
};

void test("redecodes dependent attributes/security while retaining unrelated table objects", () => {
  const fixture = decodingFixture();
  attachClrResolutionSession(fixture.tables, fixture.parsed, fixture.heaps, fixture.tables);
  const session = getClrResolutionSession(fixture.tables)!;
  assert.equal(session.enumTypes.size, 0);
  const decoded = session.resolve(new Map([["TypeRef#1 (E)", "u1"], ["E", "u1"]]));
  assert.deepEqual(decoded.customAttributes[0]!.fixedArguments, [{ type: "enum TypeRef#1 (E)", value: 254 }]);
  assert.equal(decoded.customAttributes[0]!.issues, undefined);
  assert.deepEqual(decoded.additionalTables![1]!.rows[0]!["PermissionSet"], {
    kind: "security", encoding: "binary", attributes: [{ typeName: "A", namedArguments: [
      { kind: "field", name: "B", type: "enum E", value: 254 }
    ] }]
  });
  assert.strictEqual(decoded.additionalTables![0], fixture.tables.additionalTables![0]);
  assert.strictEqual(decoded.methodDefs, fixture.tables.methodDefs);
  assert.strictEqual(getClrResolutionSession(decoded), session);
  assert.deepEqual(fixture.tables.customAttributes, []);
});

void test("keeps unresolved and truncated dependent values visible", () => {
  const fixture = decodingFixture();
  fixture.parsed.tables.get(14)!.rows[0]!["PermissionSet"] = 999;
  attachClrResolutionSession(fixture.tables, fixture.parsed, fixture.heaps, fixture.tables);
  const decoded = getClrResolutionSession(fixture.tables)!.resolve(new Map());
  assert.match(decoded.customAttributes[0]!.issues!.join(";"), /unresolved/);
  assert.equal(decoded.additionalTables![1]!.rows[0]!["PermissionSet"], null);
  assert.deepEqual(fixture.heaps.issues, ["DeclSecurity row 1 has #Blob index 999, outside the heap."]);
});

void test("decodes a shared permission blob once for a resolution context", () => {
  const fixture = decodingFixture();
  fixture.parsed.tables.get(14)!.rows.push({ PermissionSet: 7 });
  fixture.tables.additionalTables![1]!.rows.push({ PermissionSet: null });
  attachClrResolutionSession(fixture.tables, fixture.parsed, fixture.heaps, fixture.tables);
  const decoded = getClrResolutionSession(fixture.tables)!.resolve(new Map([["E", "u1"]]));
  assert.strictEqual(decoded.additionalTables![1]!.rows[0]!["PermissionSet"],
    decoded.additionalTables![1]!.rows[1]!["PermissionSet"]);
});

void test("handles absent raw rows, optional tables and a provided local enum map", () => {
  const fixture = decodingFixture();
  fixture.parsed.tables.clear();
  attachClrResolutionSession(fixture.tables, fixture.parsed, fixture.heaps,
    { ...fixture.tables, enumTypes: new Map([["E", "u1"]]) });
  const session = getClrResolutionSession(fixture.tables)!;
  assert.equal(session.enumTypes.get("E"), "u1");
  assert.ok(session.resolve(new Map()).additionalTables![1]!.rows[0]!["PermissionSet"]);
  delete fixture.tables.additionalTables;
  assert.deepEqual(session.resolve(new Map()).additionalTables, []);
  assert.deepEqual(session.resolve(new Map()).customAttributes, []);
});
