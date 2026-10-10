import assert from "node:assert/strict";
import test from "node:test";
import { createNativeAotAttributeTable } from "../../../../renderers/native-aot/attribute-tables.js";
import { createAttributedNativeAotScope } from "../../../helpers/native-aot-attributed-reflection.js";
import { createRichNativeAotScope } from "../../../helpers/native-aot-rich-reflection.js";
import { getNativeAotReflectionTypeTableModel, renderNativeAotReflection } from
  "../../../../renderers/native-aot/reflection.js";

void test("attribute tables identify every supported owner and show escaped semantic arguments", () => {
  const scope = createAttributedNativeAotScope();
  const table = createNativeAotAttributeTable([scope]);

  assert.equal(table.id, "native-aot-custom-attributes");
  assert.equal(table.rowCount, 10);
  assert.deepEqual(table.columns.map(column => column.label), ["Assembly", "Applied to", "Owner", "Attribute", "Arguments"]);
  assert.equal(table.rowAt(0)!.cells[0]!.html, "Demo&lt;Assembly>");
  assert.equal(table.rowAt(0)!.cells[3]!.html, "Example&lt;Attribute>");
  assert.match(table.rowAt(0)!.cells[4]!.html, /9007199254740993 \(long\); &quot;&lt;text>&quot;/);
  assert.match(table.rowAt(0)!.cells[4]!.html, /property Enabled: System.Boolean = false/);
  assert.deepEqual(Array.from({ length: 10 }, (_, row) => table.rowAt(row)!.cells[1]!.html),
    ["Assembly", "Module", "Type", "Type parameter", "Method", "Parameter", "Method type parameter",
      "Field", "Property", "Event"]);
  assert.deepEqual(Array.from({ length: 10 }, (_, row) => table.sortValueAt(row, 2)), [
    "Demo<Assembly>", "Demo.dll", "Demo.Container", "Demo.Container<T>", "Demo.Container.Convert",
    "Demo.Container.Convert: 1 input", "Demo.Container.Convert<T>", "Demo.Container.Value",
    "Demo.Container.Item", "Demo.Container.Changed"
  ]);
  assert.equal(table.pageSize, 100);
  assert.equal(table.tableClassName, "nativeAotAttributesTable");
  assert.match(table.rowAt(5)!.cells[2]!.html, /Convert: 1 input/);
  assert.match(table.rowAt(6)!.cells[2]!.html, /Convert&lt;T>/);
  assert.equal(table.rowAt(-1), null);
  assert.equal(table.sortValueAt(0, 3), "Example<Attribute>");
  assert.equal(table.sortValueAt(10, 0), "");
  assert.equal(table.sortValueAt(0, 9), "");
  assert.match(renderNativeAotReflection({ scopes: [scope] }), /<h4>Custom attributes<\/h4>/);
  assert.equal(getNativeAotReflectionTypeTableModel({ scopes: [scope] }, table.id)!.rowCount, 10);
});

void test("missing or marker-only attributes produce no noisy empty tables", () => {
  const scope = createRichNativeAotScope();
  assert.equal(createNativeAotAttributeTable([scope]).rowCount, 0);
  scope.attributes = [{ type: "MarkerAttribute", constructorName: ".ctor", fixedArguments: [], namedArguments: [] }];

  assert.equal(createNativeAotAttributeTable([scope]).rowAt(0)!.cells[4]!.html, "-");
  assert.doesNotMatch(renderNativeAotReflection({ scopes: [] }), /Custom attributes/);
});
