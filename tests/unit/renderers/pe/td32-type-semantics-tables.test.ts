import assert from "node:assert/strict";
import { test } from "node:test";
import { buildTd32TypeSemanticsTables } from "../../../../renderers/pe/td32-type-semantics-tables.js";
import { createTd32Info } from "../../../fixtures/pe-td32-view.js";
import type { Td32Types } from "../../../../analyzers/pe/debug/td32-type-records.js";

const infoWithTypes = (records: Td32Types["records"]) => {
  const info = createTd32Info();
  info.directories[0]!.subsections.push({ type: 0x121, module: 2, offset: 0, size: 0,
    data: { kind: "types", version: 1, records } });
  return info;
};

void test("TD32 type semantics resolve zero-based references in the current type table", () => {
  const info = infoWithTypes([
    { index: 0, type: 1, body: { attributes: 5, targetType: 0x1001 } },
    { index: 1, type: 4, nameIndex: 2, body: { count: 3, fieldList: 0x1002, attributes: 0x81,
      relation12: 0, relation16: 0x1002, relation20: 0, byteSize: { value: "56" } } },
    { index: 2, type: 0x204 }
  ]);
  const tables = buildTd32TypeSemanticsTables(info);
  assert.deepEqual(tables.find(table => table.key === "typequalifiers")!.rows,
    [["1", "2", "0", "Modifier", "0x0005", "#1 Worker", "", ""]]);
  assert.deepEqual(tables.find(table => table.key === "typeaggregates")!.rows,
    [["1", "2", "1", "Class", "3", "#2", "", "0x0081", "56",
      "+12=0x0000; +16=0x1002; +20=0x0000"]]);
});

void test("TD32 procedures, argument lists and bit fields expose meaningful bounded body fields", () => {
  const tables = buildTd32TypeSemanticsTables(infoWithTypes([
    { index: 0, type: 8, body: { returnType: 0x74, callingConvention: 0x47, functionAttributes: 0,
      parameterCount: 2, argumentList: 0x1001 } },
    { index: 1, type: 0x201, body: { argumentTypes: [0, 0x1005] } },
    { index: 2, type: 9, body: { returnType: 0, callingConvention: 0xff, functionAttributes: 1,
      parameterCount: 0, argumentList: 0x1004, classType: 0x1003, thisType: 0x1003, thisAdjustment: -4 } },
    { index: 3, type: 5, nameIndex: 99, body: { count: 0, byteSize: { leaf: 0x8005 } } },
    { index: 4, type: 0x201, body: { argumentTypes: [] } },
    { index: 5, type: 0x206, body: { underlyingType: 0x75, bitLength: 7, bitPosition: 3 } },
    { index: 6, type: 2, body: { targetType: 0, attributes: 10, memberAttributes: 2, classType: 0x1003 } }
  ]));
  assert.deepEqual(tables.find(table => table.key === "typeprocedures")!.rows,
    [["1", "2", "0", "Primitive 0x0074", "0x0047", "0x0000", "2", "#1", "", "", ""],
      ["1", "2", "2", "(none)", "0x00ff", "0x0001", "0", "#4",
        "#3 (unresolved name #99)", "#3 (unresolved name #99)", "-4"]]);
  assert.deepEqual(tables.find(table => table.key === "typearguments")!.rows,
    [["1", "2", "1", "0", "(none)"], ["1", "2", "1", "1", "#5"],
      ["1", "2", "4", "", "(empty list)"]]);
  assert.deepEqual(tables.find(table => table.key === "typebitfields")!.rows,
    [["1", "2", "5", "Primitive 0x0075", "7", "3"]]);
  assert.equal(tables.find(table => table.key === "typeaggregates")!.rows[0]![8], "Uninterpreted numeric leaf 0x8005");
  assert.deepEqual(tables.find(table => table.key === "typequalifiers")!.rows,
    [["1", "2", "6", "Pointer", "0x000a", "(none)", "0x0002", "#3 (unresolved name #99)"]]);
});

void test("TD32 type details preserve directory context, missing targets and enum raw slots", () => {
  const info = infoWithTypes([
    { index: 0, type: 7, body: { count: 0, fieldList: 0, underlyingType: 0x74, relation14: 7 } },
    { index: 1, type: 1, body: { attributes: 0, targetType: 0x1002 } },
    { index: 2, type: 7, nameIndex: 0 },
    { index: 3, type: 2, body: { attributes: 0, targetType: 0x1004 } },
    { index: 5, type: 0xffff, body: {} }
  ]);
  info.directories[0]!.subsections.shift();
  info.directories.push(info.directories[0]!);
  const tables = buildTd32TypeSemanticsTables(info);
  assert.equal(tables.find(table => table.key === "typequalifiers")!.rows[0]![5], "#2");
  assert.equal(tables.find(table => table.key === "typequalifiers")!.rows[1]![5], "(unresolved type #4)");
  assert.equal(tables.find(table => table.key === "typequalifiers")!.rows[2]![0], "2");
  assert.deepEqual(tables.find(table => table.key === "typeaggregates")!.rows[0],
    ["1", "2", "0", "Enum", "0", "(none)", "Primitive 0x0074", "", "", "+14=0x0007"]);
  assert.deepEqual(buildTd32TypeSemanticsTables({ signature: "FB09", directories: [] }), []);
});
