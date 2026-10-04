"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createMetadataOwnership } from "../../../../../../analyzers/pe/clr/metadata-list-ownership.js";
import { tableSchemaById } from "../../../../../../analyzers/pe/clr/metadata-schema.js";
import type { ClrMetadataRow, ClrParsedTable, ClrParsedTableStream }
  from "../../../../../../analyzers/pe/clr/metadata-table-reader.js";

const index = (tableId: number, row: number) => ({ table: "fixture", tableId, row, raw: row, valid: true });
const table = (tableId: number, rows: ClrMetadataRow[]): [number, ClrParsedTable] =>
  [tableId, { schema: tableSchemaById(tableId)!, rowSize: 0, rows }];
const stream = (tables: Array<[number, ClrParsedTable]>): ClrParsedTableStream => ({
  streamName: "#-", majorVersion: 2, minorVersion: 0, heapSizes: 0, largestRidLog2: 0,
  validMask: 0n, sortedMask: 0n, heapIndexSizes: { string: 2, guid: 2, blob: 2 }, rowCounts: [],
  tables: new Map(tables)
});
const reordered = (): ClrParsedTableStream => stream([
  table(2, [{ FieldList: index(3, 1), MethodList: index(5, 1) },
    { FieldList: index(3, 2), MethodList: index(5, 2) }]),
  table(3, [{ Field: index(4, 2) }, { Field: index(4, 1) }]), table(4, [{}, {}]),
  table(5, [{ Method: index(6, 2) }, { Method: index(6, 1) }]),
  table(6, [{ ParamList: index(7, 1) }, { ParamList: index(7, 2) }]),
  table(7, [{ Param: index(8, 2) }, { Param: index(8, 1) }]), table(8, [{}, {}]),
  table(0x12, [{ Parent: index(2, 2), EventList: index(0x13, 1) }]),
  table(0x13, [{ Event: index(0x14, 2) }, { Event: index(0x14, 1) }]), table(0x14, [{}, {}]),
  table(0x15, [{ Parent: index(2, 2), PropertyList: index(0x16, 1) }]),
  table(0x16, [{ Property: index(0x17, 2) }, { Property: index(0x17, 1) }]), table(0x17, [{}, {}])
]);

void test("resolves all five pointer lists in physical pointer order", () => {
  const issues: string[] = [];
  const ownership = createMetadataOwnership(reordered(), issues);
  assert.deepEqual([...ownership.fields], [[1, [2]], [2, [1]]]);
  assert.deepEqual([...ownership.methods], [[1, [2]], [2, [1]]]);
  assert.deepEqual([...ownership.parameters], [[1, [2]], [2, [1]]]);
  assert.deepEqual([...ownership.events], [[2, [2, 1]]]);
  assert.deepEqual([...ownership.properties], [[2, [2, 1]]]);
  assert.deepEqual(issues, []);
});

void test("accepts direct and terminal empty lists", () => {
  const issues: string[] = [];
  const ownership = createMetadataOwnership(stream([
    table(2, [{ FieldList: index(4, 1), MethodList: index(6, 1) },
      { FieldList: index(4, 3), MethodList: index(6, 1) }]), table(4, [{}, {}])
  ]), issues);
  assert.deepEqual([...ownership.fields], [[1, [1, 2]], [2, []]]);
  assert.deepEqual([...ownership.methods], [[1, []], [2, []]]);
  assert.deepEqual(issues, []);
  assert.equal(createMetadataOwnership(stream([]), []).fields.size, 0);
});

void test("rejects nonmonotonic and absent list starts", () => {
  const issues: string[] = [];
  const ownership = createMetadataOwnership(stream([
    table(2, [{ FieldList: index(4, 2) }, { FieldList: index(4, 1) }, {}]), table(4, [{}])
  ]), issues);
  assert.deepEqual([...ownership.fields], [[1, []], [2, []], [3, []]]);
  assert.ok(issues.some(issue => /not monotonic/.test(issue)));
});

for (const pointer of [undefined, 2, index(6, 1), index(4, 0), index(4, 3),
  { ...index(4, 1), valid: false }]) {
  void test(`rejects malformed pointer ${JSON.stringify(pointer)}`, () => {
    const parsed = reordered();
    parsed.tables.get(3)!.rows[0] = pointer === undefined ? {} : { Field: pointer };
    const issues: string[] = [];
    assert.deepEqual(createMetadataOwnership(parsed, issues).fields.get(1), []);
    assert.deepEqual(createMetadataOwnership(parsed, []).fields.get(2), [1]);
    assert.ok(issues.some(issue => /unresolved/.test(issue)));
  });
}

void test("invalidates every duplicate pointer occurrence", () => {
  const parsed = reordered();
  parsed.tables.get(3)!.rows[0] = { Field: index(4, 1) };
  const issues: string[] = [];
  assert.deepEqual([...createMetadataOwnership(parsed, issues).fields], [[1, []], [2, []]]);
  assert.ok(issues.some(issue => /duplicate pointer/.test(issue)));
});

void test("rejects a nonterminal end beyond the parsed target list", () => {
  const issues: string[] = [];
  assert.deepEqual(createMetadataOwnership(stream([
    table(2, [{ FieldList: index(4, 1) }, { FieldList: index(4, 4) }]), table(4, [{}, {}])
  ]), issues).fields.get(1), []);
  assert.match(issues[0]!, /out of bounds/);
});
