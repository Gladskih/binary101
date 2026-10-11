import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeItaniumRttiTypeNames, getItaniumRttiTypeName } from
  "../../../../analyzers/itanium-rtti/type-name.js";
import type { ItaniumRttiAnalysis } from "../../../../analyzers/itanium-rtti/types.js";
import { analyzePeItaniumRtti } from "../../../../analyzers/pe/itanium-rtti.js";
import { createPeItaniumFixture } from "../../../fixtures/pe-itanium-rtti.js";

void test("PE analysis retains encoded RTTI names and decodes their presentation", async () => {
  const fixture = createPeItaniumFixture();
  const analysis = await analyzePeItaniumRtti(fixture.reader(), fixture.core, fixture.relocations);

  const type = analysis?.types.find(item => item.name === "7Derived");
  assert.ok(type);
  assert.equal(getItaniumRttiTypeName(type), "Derived");
  assert.equal(type.name, "7Derived");
});

void test("bare template types decode while invalid names retain their raw text", async () => {
  const analysis: ItaniumRttiAnalysis = { warnings: [], types: [
    { address: 1, name: "N4demo3BoxIiEE", kind: "class", bases: [] },
    { address: 2, name: "N4demo", kind: "class", bases: [] }
  ] };

  await decodeItaniumRttiTypeNames(analysis);

  assert.equal(getItaniumRttiTypeName(analysis.types[0]!), "demo::Box<int>");
  assert.equal(getItaniumRttiTypeName(analysis.types[1]!), "N4demo");
  assert.deepEqual(analysis.warnings, []);
});

void test("failed RTTI loading preserves raw names and warns once", async () => {
  const analysis: ItaniumRttiAnalysis = { warnings: [], types: [
    { address: 1, name: "4Type", kind: "class", bases: [] },
    { address: 2, name: "4Base", kind: "class", bases: [] }
  ] };

  await decodeItaniumRttiTypeNames(analysis, () => Promise.reject(new Error("offline")));

  assert.equal(getItaniumRttiTypeName(analysis.types[0]!), "4Type");
  assert.deepEqual(analysis.warnings, ["Itanium RTTI name demangling unavailable: offline"]);
});
