import assert from "node:assert/strict";
import { test } from "node:test";
import { renderNativeAotInitializers } from "../../../../renderers/native-aot/initializers.js";
import { createNativeAotInitializerFixture } from "../../../helpers/native-aot-initializer-fixture.js";

void test("renders initializer seed counts and escapes visible warnings", () => {
  const fixture = createNativeAotInitializerFixture();

  // ModuleHeaders.cs section IDs: EagerCctor = 205, ModuleInitializerList = 213.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
  const html = renderNativeAotInitializers([
    { sectionType: 205, targetRvas: fixture.codeRvas, warnings: [] },
    { sectionType: 213, targetRvas: [], warnings: ["bad <table>"] }
  ]);

  assert.match(html, /Eager class constructors/);
  assert.match(html, /Module initializers/);
  assert.ok(html.includes(`>${fixture.codeRvas.length}</td>`));
  assert.match(html, /bad &lt;table>/);
  assert.match(html, /disassembler/i);
});

void test("omits absent initializer tables", () => {
  assert.equal(renderNativeAotInitializers(undefined), "");
  assert.equal(renderNativeAotInitializers([]), "");
});
