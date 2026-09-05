"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { DOMParser } from "@xmldom/xmldom";
import { createNativeAotReflectionTypeTableModel, renderNativeAotReflection } from
  "../../../../renderers/native-aot/reflection.js";
import type { NativeAotReflectionMetadata } from
  "../../../../analyzers/native-aot/format.js";

void test("renderNativeAotReflection renders scope, type, and method names", () => {
  const metadata: NativeAotReflectionMetadata = {
    scopes: [{
      name: "Demo<Assembly>",
      moduleName: "Demo.dll",
      version: { major: 1, minor: 2, build: 3, revision: 4 },
      types: [{ namespace: "Example", name: "Program", methods: ["Main", "Run<Wait>"],
        fields: ["Count", "<Name>k__BackingField"] }, {
        namespace: "",
        name: "Marker",
        methods: [],
        fields: []
      }]
    }]
  };

  const html = renderNativeAotReflection(metadata);

  assert.ok(html.includes("Reflection scopes"));
  assert.ok(html.includes("retained for runtime reflection"));
  assert.ok(html.includes("Demo&lt;Assembly>"));
  assert.ok(html.includes("Demo.dll"));
  assert.ok(html.includes("1.2.3.4"));
  assert.ok(html.includes("Example.Program"));
  assert.ok(html.includes("Run&lt;Wait>"));
  assert.ok(html.includes("Main, Run&lt;Wait>"));
  assert.ok(html.includes("Count, &lt;Name>k__BackingField"));
  assert.ok(html.includes('class="nativeAotTable__compact peNumeric">Fields</th>'));
  assert.match(html, /peNumeric">2<\/td><\/tr>/);
  assert.match(html, /nativeAotTypesTable__fields"[^>]*>-<\/td>/);
  assert.ok(html.includes("do not include signatures or code addresses"));
  assert.ok(html.includes('class="table nativeAotScopesTable"'));
  assert.ok(html.includes('class="nativeAotTable__compact peNumeric">Methods</th>'));
  assert.ok(html.includes('class="table nativeAotTypesTable"'));
  assert.match(html, /nativeAotTypesTable__identity"[^>]*>Marker<\/td>/);
  assert.match(html, /nativeAotTypesTable__methods"[^>]*>-<\/td>/);
});

void test("renderNativeAotReflection renders warnings without empty tables", () => {
  const html = renderNativeAotReflection({ scopes: [], warnings: ["bad <metadata>"] });

  assert.ok(html.includes("Warnings"));
  assert.ok(html.includes("bad &lt;metadata>"));
  assert.ok(!html.includes("<table"));
});

void test("renderNativeAotReflection omits an empty graph", () => {
  assert.equal(renderNativeAotReflection({ scopes: [] }), "");
});

void test("renderNativeAotReflection pages a long type list", () => {
  // The 101st row crosses the renderer's 100-row UI page size.
  const types = Array.from({ length: 101 }, (_, index) => ({
    namespace: "Demo",
    name: `Type${index}`,
    methods: [],
    fields: []
  }));

  const html = renderNativeAotReflection({
    scopes: [{
      name: "LargeAssembly",
      moduleName: "LargeAssembly.dll",
      version: { major: 1, minor: 0, build: 0, revision: 0 },
      types
    }]
  });

  assert.ok(html.includes('data-paged-sortable-table-id="native-aot-reflection-types"'));
  assert.ok(html.includes("Showing 1-100 of 101"));
  assert.ok(html.includes("Demo.Type99"));
  assert.ok(!html.includes("Demo.Type100"));
});

void test("reflection tables keep headers and counts aligned across multiple scopes", () => {
  const scopes = [{
    name: "First", moduleName: "First.dll",
    version: { major: 1, minor: 2, build: 3, revision: 4 },
    types: [{ namespace: "", name: "Record", methods: ["Run"], fields: ["Count", "Name"] }]
  }, {
    name: "Second", moduleName: "Second.dll",
    version: { major: 4, minor: 3, build: 2, revision: 1 }, types: []
  }];

  const document = new DOMParser({ onError: (_level, message) => assert.fail(message) })
    .parseFromString(`<div>${renderNativeAotReflection({ scopes })}</div>`, "text/html");
  const tables = Array.from(document.getElementsByTagName("table"));
  const scopeRows = Array.from(tables[0]!.getElementsByTagName("tr"));

  assert.deepEqual(Array.from(scopeRows[0]!.getElementsByTagName("th"))
    .map(cell => cell.textContent), ["Assembly", "Module", "Assembly version", "Types", "Methods", "Fields"]);
  assert.deepEqual(scopeRows.slice(1).map(row => Array.from(row.getElementsByTagName("td"))
    .map(cell => cell.textContent)), [
    ["First", "First.dll", "1.2.3.4", "1", "1", "2"],
    ["Second", "Second.dll", "4.3.2.1", "0", "0", "0"]
  ]);
  assert.equal(tables.length, 2);
  assert.deepEqual(Array.from(tables[1]!.getElementsByTagName("th")).map(cell => cell.textContent),
    ["Assembly", "Type", "Methods", "Fields"]);
});

void test("reflection table model exposes sortable field names with matching column classes", () => {
  const model = createNativeAotReflectionTypeTableModel([{
    name: "App", moduleName: "App.dll",
    version: { major: 1, minor: 0, build: 0, revision: 0 },
    types: [{ namespace: "", name: "Record", methods: ["Run"], fields: ["<Count>", "Name"] }]
  }]);

  assert.deepEqual(model.columns, [
    { label: "Assembly", className: "nativeAotTypesTable__identity" },
    { label: "Type", className: "nativeAotTypesTable__identity" },
    { label: "Methods", className: "nativeAotTypesTable__methods" },
    { label: "Fields", className: "nativeAotTypesTable__fields" }
  ]);
  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.className),
    model.columns.map(column => column.className));
  assert.equal(model.sortValueAt(0, 3), "<Count>, Name");
  assert.equal(model.rowAt(0)?.cells[3]?.html, "&lt;Count>, Name");
});
