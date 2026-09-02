"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderNativeAotReflection } from
  "../../../../renderers/pe/native-aot-reflection.js";
import type { PeNativeAotReflectionMetadata } from
  "../../../../analyzers/pe/native-aot/format.js";

void test("renderNativeAotReflection renders scope, type, and method names", () => {
  const metadata: PeNativeAotReflectionMetadata = {
    scopes: [{
      name: "Demo<Assembly>",
      moduleName: "Demo.dll",
      version: { major: 1, minor: 2, build: 3, revision: 4 },
      types: [{ namespace: "Example", name: "Program", methods: ["Main", "Run<Wait>"] }, {
        namespace: "",
        name: "Marker",
        methods: []
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
  assert.ok(html.includes("do not include signatures or code addresses"));
  assert.ok(html.includes('class="table peNativeAotScopesTable"'));
  assert.ok(html.includes('class="peNativeAotTable__compact peNumeric">Methods</th>'));
  assert.ok(html.includes('class="table peNativeAotTypesTable"'));
  assert.match(html, /peNativeAotTypesTable__identity"[^>]*>Marker<\/td>/);
  assert.match(html, /peNativeAotTypesTable__methods"[^>]*>-<\/td>/);
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
    methods: []
  }));

  const html = renderNativeAotReflection({
    scopes: [{
      name: "LargeAssembly",
      moduleName: "LargeAssembly.dll",
      version: { major: 1, minor: 0, build: 0, revision: 0 },
      types
    }]
  });

  assert.ok(html.includes('data-paged-sortable-table-id="pe-native-aot-reflection-types"'));
  assert.ok(html.includes("Showing 1-100 of 101"));
  assert.ok(html.includes("Demo.Type99"));
  assert.ok(!html.includes("Demo.Type100"));
});
