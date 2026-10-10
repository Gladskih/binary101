import assert from "node:assert/strict";
import { test } from "node:test";
import { createNativeAotDefinitionTable, createNativeAotMemberTable, getNativeAotDefinitionTable } from
  "../../../../renderers/native-aot/member-tables.js";
import { createRichNativeAotScope } from "../../../helpers/native-aot-rich-reflection.js";

void test("shows type definitions, layout, interfaces and generic constraints", () => {
  const scope = createRichNativeAotScope();

  const model = createNativeAotDefinitionTable([scope]);

  assert.equal(model.rowCount, 1);
  assert.equal(model.id, "native-aot-type-definitions");
  assert.equal(model.rowAt(0)?.cells[0]?.html, "Demo&lt;Assembly>");
  assert.equal(model.rowAt(0)?.cells[1]?.html, "Demo.Container");
  assert.equal(model.rowAt(0)?.cells[2]?.html, "0x1");
  assert.equal(model.rowAt(0)?.cells[3]?.html, "System.Object");
  assert.equal(model.rowAt(0)?.cells[4]?.html, "Demo.IMarker");
  assert.equal(model.rowAt(0)?.cells[5]?.html, "32");
  assert.equal(model.rowAt(0)?.cells[6]?.html, "8");
  assert.equal(model.columns[5]?.className, "peNumeric");
  assert.equal(model.rowAt(0)?.cells[5]?.className, "peNumeric");
  assert.equal(model.rowAt(0)?.cells[1]?.className, "");
  assert.match(model.rowAt(0)?.cells[7]?.html ?? "", /flags=0x4/);
  assert.equal(model.rowAt(-1), null);
  assert.equal(model.sortValueAt(0, 1), "Demo.Container");
  assert.equal(model.sortValueAt(100, 1), "");
});

void test("renders methods, fields, properties and events without inventing missing metadata", () => {
  const model = createNativeAotMemberTable([createRichNativeAotScope()]);

  assert.equal(model.rowCount, 8);
  assert.equal(model.id, "native-aot-member-definitions");
  assert.equal(model.rowAt(0)?.cells[4]?.html,
    "!!0 Convert&lt;T>(!0&, ..., System.String)");
  assert.match(model.rowAt(0)?.cells[6]?.html ?? "", /impl=0x1; cc=0x20/);
  assert.match(model.rowAt(0)?.cells[6]?.html ?? "", /Demo.IMarker/);
  assert.equal(model.rowAt(1)?.cells[5]?.html, "-");
  assert.equal(model.rowAt(1)?.cells[6]?.html, "-");
  assert.equal(model.rowAt(2)?.cells[6]?.html, "offset=12");
  assert.equal(model.rowAt(3)?.cells[6]?.html, "-");
  assert.equal(model.rowAt(4)?.cells[4]?.html, "System.String (System.Int32)");
  assert.match(model.rowAt(4)?.cells[6]?.html ?? "", /get_Item/);
  assert.equal(model.rowAt(5)?.cells[4]?.html, "? ()");
  assert.equal(model.rowAt(6)?.cells[4]?.html, "System.EventHandler");
  assert.match(model.rowAt(6)?.cells[6]?.html ?? "", /add_Changed/);
  assert.equal(model.rowAt(7)?.cells[4]?.html, "?");
});

void test("resolves definition tables and bounds invalid row indices", () => {
  const scopes = [createRichNativeAotScope()];

  assert.equal(getNativeAotDefinitionTable(scopes, "native-aot-type-definitions")?.rowCount, 1);
  assert.equal(getNativeAotDefinitionTable(scopes, "native-aot-member-definitions")?.rowCount, 8);
  assert.equal(getNativeAotDefinitionTable(scopes, "unknown"), null);
  assert.equal(createNativeAotMemberTable(scopes).rowAt(100), null);
  assert.equal(createNativeAotMemberTable([]).rowCount, 0);
});

void test("labels every definition column and retains parameter flags and generic names", () => {
  const types = createNativeAotDefinitionTable([createRichNativeAotScope()]);
  const members = createNativeAotMemberTable([createRichNativeAotScope()]);

  assert.deepEqual(types.columns.map(column => column.label),
    ["Assembly", "Type", "Flags", "Base type", "Interfaces", "Size", "Packing", "Generic parameters"]);
  assert.deepEqual(members.columns.map(column => column.label),
    ["Assembly", "Type", "Kind", "Name", "Signature", "Flags", "Metadata"]);
  assert.equal(types.rowAt(0)?.cells[7]?.html, "T (#0, flags=0x4, kind=0)");
  assert.deepEqual(members.rowAt(0)?.cells.map(cell => cell.html), [
    "Demo&lt;Assembly>", "Demo.Container", "Method", "Convert",
    "!!0 Convert&lt;T>(!0&, ..., System.String)", "0x6",
    "impl=0x1; cc=0x20; 1: input (flags=0x10); T (#0, flags=0x8, kind=1, Demo.IMarker)"
  ]);
});

void test("identifies field, property and event declarations with their accessor flags", () => {
  const model = createNativeAotMemberTable([createRichNativeAotScope()]);

  assert.deepEqual(model.rowAt(2)?.cells.slice(2).map(cell => cell.html),
    ["Field", "Value", "System.Int32 Value", "0x6", "offset=12"]);
  assert.deepEqual(model.rowAt(4)?.cells.slice(2).map(cell => cell.html),
    ["Property", "Item", "System.String (System.Int32)", "0x0", "get_Item (0x2)"]);
  assert.deepEqual(model.rowAt(6)?.cells.slice(2).map(cell => cell.html),
    ["Event", "Changed", "System.EventHandler", "0x0", "add_Changed (0x8)"]);
});
void test("member metadata explains retained field, property and parameter defaults", () => {
  const scope = createRichNativeAotScope();
  scope.types[0]!.fields[0]!.defaultValue = { type: "long", value: "9007199254740993" };
  scope.types[0]!.definition!.properties[0]!.defaultValue = { type: "string", value: "<default>" };
  scope.types[0]!.methods[0]!.parameters![0]!.defaultValue = { type: "bool", value: false };

  const model = createNativeAotMemberTable([scope]);

  assert.match(model.rowAt(0)!.cells[6]!.html, /input.* = false \(bool\)/);
  assert.match(model.rowAt(2)!.cells[6]!.html, /Default: 9007199254740993 \(long\)/);
  assert.match(model.rowAt(4)!.cells[6]!.html, /Default: &quot;&lt;default>&quot;/);
});
