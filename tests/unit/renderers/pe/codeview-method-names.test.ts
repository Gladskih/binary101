import assert from "node:assert/strict";
import { test } from "node:test";
import type { LegacyCodeViewTypeRecord } from "../../../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { codeViewMethodNames } from "../../../../renderers/pe/codeview-method-names.js";
import { createCodeViewTypeFormatter, indexCodeViewTypes } from "../../../../renderers/pe/codeview-type-names.js";

void test("CodeView method names bind overloads, preserve differing attributes and deduplicate exact references", () => {
  const records: LegacyCodeViewTypeRecord[] = [
    { type: 0x1505, index: 0x1000, name: "Packet" },
    { type: 0x1203, index: 0x1001, members: [
      { type: 0x1511, name: "read", typeIndex: 0x1002, attributes: 3, vtableOffset: 0 },
      { type: 0x1511, name: "read", typeIndex: 0x1002, attributes: 3, vtableOffset: 0 },
      { type: 0x1511, name: "write", typeIndex: 0x1002, attributes: 3, vtableOffset: 0 },
      { type: 0x1511, name: "read", typeIndex: 0x1002, attributes: 7, vtableOffset: 0 },
      { type: 0x1511, name: "read", typeIndex: 0x1002, attributes: 3, vtableOffset: 8 },
      { type: 0x150f, name: "read", typeIndex: 0x1003 },
      { type: 0x150f, typeIndex: 0x2000 }, { type: 0x1511, typeIndex: 0x2001 },
      { type: 0x150d, name: "data", typeIndex: 0x1002 }, { type: 0x1511, name: "incomplete" },
      { type: 0x150f, name: "notMethods", typeIndex: 0x1005 }
    ] },
    { type: 0x1009, index: 0x1002, shape: { kind: "memberFunction", classType: 0x1000,
      returnType: 0x74, thisType: 0, thisAdjustment: 0, parameterCount: 0,
      argumentList: 0x1005, callingConvention: 0, attributes: 0 } },
    { type: 0x1206, index: 0x1003, shape: { kind: "methods", methods: [
      { typeIndex: 0x1002, attributes: 3, vtableOffset: 0 }, { typeIndex: 0x1004, attributes: 7 }
    ] } }, { type: 0x7777, index: 0x1004 },
    { type: 0x1201, index: 0x1005, shape: { kind: "arguments", types: [] } }
  ];
  const indexed = indexCodeViewTypes(records);
  const names = codeViewMethodNames(records, indexed, createCodeViewTypeFormatter(indexed));
  assert.deepEqual(names.get(0x1002), [
    { name: "Packet::read", attributes: 3, vtableOffset: 0 },
    { name: "Packet::write", attributes: 3, vtableOffset: 0 },
    { name: "Packet::read", attributes: 7, vtableOffset: 0 },
    { name: "Packet::read", attributes: 3, vtableOffset: 8 }
  ]);
  assert.deepEqual(names.get(0x1004), [{ name: "read", attributes: 7, vtableOffset: undefined }]);
  assert.deepEqual(names.get(0x2001), [{ name: "(unnamed method)", attributes: undefined, vtableOffset: undefined }]);
  assert.equal(names.size, 3);
});

void test("CodeView imported and ambiguous field-list namespaces never bind method names to local types", () => {
  const records: LegacyCodeViewTypeRecord[] = [
    { type: 0x1203, members: [{ type: 0x1511, name: "external", typeIndex: 0x1002 }] },
    { type: 0x1203, index: 0x1000, members: [{ type: 0x1511, name: "first", typeIndex: 0x1002 }] },
    { type: 0x1203, index: 0x1000, members: [{ type: 0x1511, name: "second", typeIndex: 0x1002 }] }
  ];
  const indexed = indexCodeViewTypes(records);
  assert.equal(codeViewMethodNames(records, indexed, createCodeViewTypeFormatter(indexed)).size, 0);
});
