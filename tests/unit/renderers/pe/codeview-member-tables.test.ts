import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCodeViewMemberTables } from "../../../../renderers/pe/codeview-member-tables.js";
import { codeViewInfoWithTypes } from "../../../fixtures/pe-codeview-callables.js";

void test("CodeView 16-bit enumerators retain their exact values in the member table", () => {
  const table = buildCodeViewMemberTables(codeViewInfoWithTypes([{ type: 0x204,
    members: [{ type: 0x403, name: "negative", value: "-128" }] }]))[0]!;
  assert.equal(table.rows[0]?.[5], "-128");
});

// CV_methodprop_e, independent labels from Microsoft's cvconst.h.
for (const [property, label] of [[0, "public"], [1, "public; virtual"],
  [2, "public; static"], [3, "public; friend"], [4, "public; introducing virtual"],
  [5, "public; pure virtual"], [6, "public; pure introducing virtual"]] as const) {
  void test(`CodeView method property ${property} has a readable label`, () => {
    const table = buildCodeViewMemberTables(codeViewInfoWithTypes([{ type: 0x1203,
      members: [{ type: 0x1511, name: "method", attributes: 3 | property << 2 }] }]))[0]!;
    assert.equal(table.rows[0]?.[6], label);
  });
}

void test("CodeView members show exact enum values, field types and byte offsets in one readable table", () => {
  const tables = buildCodeViewMemberTables(codeViewInfoWithTypes([
    { type: 0x1203, index: 0x1000, members: [
      { type: 0x1502, name: "largest", attributes: 3, value: "18446744073709551615" },
      { type: 0x150d, name: "count", attributes: 1, typeIndex: 0x74, offset: "12" },
      { type: 0x150e, name: "total", attributes: 2, typeIndex: 0x75 },
      { type: 0x150f, name: "read", typeIndex: 0x1001, methodCount: 2 }
    ] }, { type: 0x1206, index: 0x1001 }
  ]));
  assert.equal(tables[0]?.key, "members");
  assert.equal(tables[0]?.title, "Member and enumerator names");
  assert.deepEqual(tables[0]?.columns, ["Directory", "Module", "Member kind", "Name", "Type", "Value / placement", "Properties", "Owner type"]);
  assert.deepEqual(tables[0]?.rows, [
    ["1", "1", "Enumerator", "largest", "—", "18446744073709551615", "public", "unassociated"],
    ["1", "1", "Data member", "count", "int32", "offset: 12 bytes", "private", "unassociated"],
    ["1", "1", "Static data member", "total", "uint32", "—", "protected", "unassociated"],
    ["1", "1", "Overloaded method", "read", "Methods #4097", "—", "2 declared overloads", "unassociated"]
  ]);
});

void test("CodeView fields retain all owning classes across continuation lists", () => {
  const table = buildCodeViewMemberTables(codeViewInfoWithTypes([
    { type: 0x1505, index: 0x1000, name: "Packet", shape: { kind: "aggregate",
      memberCount: 2, properties: 0, fieldList: 0x1001 } },
    { type: 0x1203, index: 0x1001, members: [{ type: 0x150d, name: "first" },
      { type: 0x1404, continuation: 0x1002 }] },
    { type: 0x1203, index: 0x1002, members: [{ type: 0x150d, name: "last" }] },
    { type: 0x1505, index: 0x1003, name: "Alias", shape: { kind: "aggregate",
      memberCount: 2, properties: 0, fieldList: 0x1001 } },
    { type: 0x1505, name: "External", shape: { kind: "aggregate",
      memberCount: 2, properties: 0, fieldList: 0x1001 } },
    { type: 0x1505, index: 0x1004, name: "Forward", shape: { kind: "aggregate",
      memberCount: 0, properties: 0x80, fieldList: 0 } }
  ]))[0]!;
  assert.deepEqual(table.rows.map(row => row[7]), ["Packet; Alias", "Packet; Alias", "Packet; Alias"]);
});

void test("CodeView cyclic field-list ownership stays visible and orphan references stay unresolved", () => {
  const table = buildCodeViewMemberTables(codeViewInfoWithTypes([
    { type: 0x1505, index: 0x1000, name: "Packet", shape: { kind: "aggregate",
      memberCount: 1, properties: 0, fieldList: 0x1001 } },
    { type: 0x1203, index: 0x1001, members: [{ type: 0x1404, continuation: 0x1001 }] },
    { type: 0x1203, index: 0x1002, members: [{ type: 0x1404, continuation: 0x2000 }] },
    { type: 0x1203, members: [{ type: 0x150d, name: "external", typeIndex: 0x1000 }] }
  ]))[0]!;
  assert.equal(table.rows[0]?.[7], "Packet (cyclic field-list continuation #4097)");
  assert.equal(table.rows[1]?.[7], "unassociated; missing field list #8192");
  assert.equal(table.rows[2]?.[7], "unresolved namespace");
  assert.equal(table.rows[2]?.[4], "unresolved type #4096");
});

void test("CodeView missing virtual-base numbers remain unavailable without fake zero offsets", () => {
  const rows = buildCodeViewMemberTables(codeViewInfoWithTypes([{ type: 0x1203, members: [
    { type: 0x1402, virtualBasePointer: 0 }, { type: 0x40d, vtableOffset: -8 }
  ] }]))[0]!.rows;
  assert.equal(rows[0]?.[5], "vbptr offset: unavailable bytes; vbtable index: unavailable");
  assert.equal(rows[1]?.[5], "vtable offset: -8 bytes");
});

void test("CodeView virtual bases and introducing methods distinguish offsets from table indices", () => {
  const table = buildCodeViewMemberTables(codeViewInfoWithTypes([{ type: 0x1203, members: [
    { type: 0x1401, typeIndex: 0x1001, attributes: 3, virtualBasePointer: 0x674,
      offset: "16", virtualBaseTableIndex: "2" },
    { type: 0x1511, name: "read", typeIndex: 0x1002, attributes: 19, vtableOffset: 32 },
    { type: 0x1404, continuation: 0x1003 }
  ] }]))[0]!;
  assert.equal(table.rows[0]?.[3], "(unnamed)");
  assert.equal(table.rows[0]?.[5], "vbptr offset: 16 bytes; vbtable index: 2");
  assert.equal(table.rows[0]?.[6], "public; virtual base pointer: near64 pointer to int32");
  assert.equal(table.rows[1]?.[5], "vtable offset: 32 bytes");
  assert.equal(table.rows[1]?.[6], "public; introducing virtual");
  assert.equal(table.rows[2]?.[6], "continues field list #4099");
});

void test("CodeView member attribute flags and undecoded numbers remain visible", () => {
  const table = buildCodeViewMemberTables(codeViewInfoWithTypes([{ type: 0x1203, members: [
    { type: 0x1502, name: "unknownValue", attributes: 0x83ff },
    { type: 0x150d, name: "unknownOffset", typeIndex: 0x2000 },
    { type: 0x150e, name: "plain", attributes: 0 }
  ] }]))[0]!;
  assert.equal(table.rows[0]?.[5], "unavailable");
  assert.match(table.rows[0]?.[6] ?? "", /unknown method property 7/);
  assert.match(table.rows[0]?.[6] ?? "", /unknown attribute bits 0x8000/);
  assert.match(table.rows[0]?.[6] ?? "", /compiler-generated declaration; not inheritable; not constructible/);
  assert.match(table.rows[0]?.[6] ?? "", /compiler-generated definition; sealed/);
  assert.equal(table.rows[1]?.[4], "unresolved type #8192");
  assert.equal(table.rows[1]?.[5], "unavailable");
  assert.equal(table.rows[2]?.[6], "none");
  assert.deepEqual(buildCodeViewMemberTables({ signature: "NB09", directories: [] }), []);
});
