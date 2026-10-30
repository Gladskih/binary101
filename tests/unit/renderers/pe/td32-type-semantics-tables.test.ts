import assert from "node:assert/strict";
import { test } from "node:test";
import { buildTd32TypeSemanticsTables } from "../../../../renderers/pe/td32-type-semantics-tables.js";
import { createTd32Info } from "../../../fixtures/pe-td32-view.js";
import type { Td32Types } from "../../../../analyzers/pe/debug/td32-type-records.js";

const infoWithTypes = (records: Td32Types["records"]) => {
  const info = createTd32Info();
  info.directories[0]!.subsections = info.directories[0]!.subsections.filter(section => section.data?.kind !== "types");
  info.directories[0]!.subsections.push({ type: 0x121, module: 2, offset: 0, size: 0,
    data: { kind: "types", version: 1, records } });
  return info;
};

void test("TD32 named aggregates lead with shared names, size, counts and documented flags", () => {
  const tables = buildTd32TypeSemanticsTables(infoWithTypes([
    { index: 0, type: 4, nameIndex: 2, body: { count: 3, attributes: 0x183,
      relation12: 0, relation16: 0x1002, relation20: 0, byteSize: { value: "56" } } },
    { index: 1, type: 5, nameIndex: 1, body: { count: 0, attributes: 0 } },
    { index: 2, type: 7, nameIndex: 4, body: { count: 4, relation14: 0x1000 } },
    { index: 3, type: 5, body: { count: 1, attributes: 0 } },
    { index: 4, type: 4, nameIndex: 99, body: { count: 1, attributes: 0 } }
  ]));
  assert.deepEqual(tables.find(table => table.key === "typeaggregates")!.columns,
    ["Name", "Kind", "Bytes", "Members/values", "Attributes", "Directory", "Module"]);
  assert.deepEqual(tables.find(table => table.key === "typeaggregates")!.rows,
    [["Worker", "Class", "56", "3", "Packed, Has constructor, Forward reference, Has destructor", "1", "2"],
      ["<unit>.pas", "Structure", "Not decoded", "0", "None", "1", "2"],
      ["unused type name", "Enum", "Not recorded", "4", "Not recorded", "1", "2"]]);
  assert.ok(tables.find(table => table.key === "typestatistics")!.rows.some(row =>
    row.join("|") === "Unresolved relation slots|Nonzero|2"));
  assert.ok(!JSON.stringify(tables).includes("0x1002"));
});

void test("TD32 anonymous types produce grouped semantic statistics instead of identifier matrices", () => {
  const tables = buildTd32TypeSemanticsTables(infoWithTypes([
    { index: 0, type: 1, body: { attributes: 5, targetType: 0x1005 } },
    { index: 1, type: 1, body: { attributes: 5, targetType: 0x1006 } },
    { index: 2, type: 2, body: { attributes: 0x24a, targetType: 0x1005 } },
    { index: 3, type: 8, body: { callingConvention: 0x47, parameterCount: 2, functionAttributes: 0 } },
    { index: 4, type: 9, body: { callingConvention: 0x47, parameterCount: 2, functionAttributes: 1 } },
    { index: 5, type: 0x201, body: { argumentTypes: [0x74, 0x1002] } },
    { index: 6, type: 0x201, body: { argumentTypes: [] } },
    { index: 7, type: 0x206, body: { bitLength: 7, bitPosition: 3, underlyingType: 0x75 } }
  ]));
  assert.deepEqual(tables.map(table => table.key), ["typestatistics"]);
  const rows = tables[0]!.rows;
  assert.ok(rows.some(row => row.join("|") === "Modifier qualifiers|Const, Unaligned|2"));
  assert.ok(rows.some(row => row.join("|") === "Pointer mode|Pointer to data member|1"));
  assert.ok(rows.some(row => row.join("|") === "Pointer representation|Near 32-bit|1"));
  assert.ok(rows.some(row => row.join("|") === "Pointer qualifiers|Const|1"));
  assert.ok(rows.some(row => row.join("|") === "Calling convention|Near stdcall, Variable arguments|2"));
  assert.ok(rows.some(row => row.join("|") === "Procedure parameter count|2|2"));
  assert.ok(rows.some(row => row.join("|") === "Argument-list length|0|1"));
  assert.ok(rows.some(row => row.join("|") === "Arguments|Total|2"));
  assert.ok(rows.some(row => row.join("|") === "Bit-field length|7 bits|1"));
  assert.ok(rows.some(row => row.join("|") === "Bit-field position|3 bits|1"));
  assert.ok(!JSON.stringify(tables).includes("0x1005"));
});

void test("TD32 type summaries expose unknown mappings and missing names without guesses", () => {
  const info = infoWithTypes([
    { index: 0, type: 1, body: { attributes: 0x8000 } },
    { index: 1, type: 2, body: { attributes: 0xffff } },
    { index: 2, type: 8, body: { callingConvention: 0xff, parameterCount: 0 } },
    { index: 3, type: 4, nameIndex: 2, body: { attributes: 0x8000, byteSize: { leaf: 0x8005 } } },
    { index: 4, type: 5, nameIndex: 4 },
    { index: 5, type: 7, nameIndex: 0 },
    { index: 6, type: 0x7777 }
  ]);
  const tables = buildTd32TypeSemanticsTables(info);
  assert.deepEqual(tables[0]!.rows, [["Worker", "Class", "Numeric size not interpreted", "Not decoded", "Unknown bits", "1", "2"],
    ["unused type name", "Structure", "Not decoded", "Not decoded", "Not decoded", "1", "2"]]);
  assert.ok(JSON.stringify(tables).includes("Unknown pointer mode"));
  assert.ok(JSON.stringify(tables).includes("Unknown pointer representation"));
  assert.ok(JSON.stringify(tables).includes("Unknown calling convention"));
  info.directories[0]!.subsections.shift();
  assert.ok(buildTd32TypeSemanticsTables(info).every(table => table.key === "typestatistics"));
  assert.deepEqual(buildTd32TypeSemanticsTables({ signature: "FB09", directories: [] }), []);
});

void test("TD32 partial bodies report unavailable characteristics instead of inventing defaults", () => {
  const tables = buildTd32TypeSemanticsTables(infoWithTypes([
    { index: 0, type: 1, body: {} }, { index: 1, type: 2, body: {} },
    { index: 2, type: 8, body: {} }, { index: 3, type: 9, body: {} },
    { index: 4, type: 0x201, body: {} }, { index: 5, type: 0x206, body: {} },
    { index: 6, type: 0x7777, body: {} }
  ]));
  assert.deepEqual(tables.map(table => table.key), ["typestatistics"]);
  assert.ok(tables[0]!.rows.some(row => row.join("|") === "Pointer mode|Not decoded|1"));
  assert.ok(tables[0]!.rows.some(row => row.join("|") === "Calling convention|Not decoded|2"));
  assert.ok(tables[0]!.rows.some(row => row.join("|") === "Argument lists|Not decoded|1"));
  assert.ok(tables[0]!.rows.some(row => row.join("|") === "Bit-field length|Not decoded|1"));
  assert.ok(!tables[0]!.rows.some(row => row[0] === "Arguments"));
});

void test("TD32 type summary integrates named children and summarizes extended anonymous families",()=>{
  const info=infoWithTypes([
    {index:0,type:4,nameIndex:2,body:{fieldList:0x1001}},
    {index:1,type:0x204,body:{fields:[{type:0x406,nameIndex:1,targetType:0x74}]}},
    {index:2,type:0x207,body:{methods:[]}},
    {index:3,type:10,body:{descriptors:[5,5]}},
    {index:4,type:0x34,body:{closureTail:[0,0]}},
    {index:5,type:0x35,body:{attributes:1}},
    {index:6,type:0x35,body:{attributes:0}},
    {index:7,type:0x35,body:{}},
    {index:8,type:0x34,body:{}},
    {index:9,type:0x204,body:{}},
    {index:10,type:0x207,body:{}},
    {index:11,type:10,body:{}}
  ]);
  info.directories.push(info.directories[0]!);
  const tables=buildTd32TypeSemanticsTables(info);
  assert.equal(tables.find(table=>table.key==="typemembers")!.rows.length,2);
  assert.ok(tables.find(table=>table.key==="typestatistics")!.rows.some(row=>
    row.join("|")==="Pascal properties|Default|2"));
  assert.ok(tables.find(table=>table.key==="typestatistics")!.rows.some(row=>
    row.join("|")==="Vtable descriptors|Total|4"));
});
