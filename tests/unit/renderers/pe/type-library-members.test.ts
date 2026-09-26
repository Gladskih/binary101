import assert from "node:assert/strict";
import { test } from "node:test";
import { renderTypeLibraryMembers } from "../../../../renderers/pe/type-library-members.js";
import { addTypeLibraryPreview } from "../../../../analyzers/pe/resources/preview/type-library.js";
import { createMsftLibrary } from "../../../fixtures/type-library.js";

const library = () => addTypeLibraryPreview(createMsftLibrary(), "TYPELIB", null)!
  .preview!.typeLibrary!.analysis!;

void test("member renderer exposes signatures, parameters, defaults and metadata", () => {
  const analysis = library();
  const html = renderTypeLibraryMembers(analysis, analysis.types[0]!);
  assert.match(html, /method Run/);
  assert.match(html, /long\*/);
  assert.match(html, /stdcall/);
  assert.match(html, /long: 42/);
  assert.match(html, /long: -123/);
  assert.match(html, /DISPID/);
});

void test("member renderer escapes hostile names and presents unknown enum values", () => {
  const analysis = library();
  const type = analysis.types[0]!;
  type.functions[0]!.name = "<script>";
  type.functions[0]!.invocation = 99;
  type.functions[0]!.callingConvention = 99;
  type.functions[0]!.kind = 99;
  type.functions[0]!.parameters[0]!.name = null;
  type.functions[0]!.parameters[0]!.customData = analysis.customData;
  type.variables[0]!.kind = 99;
  type.variables[0]!.instanceOffset = 4;
  assert.match(renderTypeLibraryMembers(analysis, type), /INVOKEKIND\(99\)/);
  assert.match(renderTypeLibraryMembers(analysis, type), /&lt;script>/);
  assert.match(renderTypeLibraryMembers(analysis, type), /Parameter \?/);
});

void test("member renderer handles absent names and interface custom data", () => {
  const analysis = library();
  const type = analysis.types[0]!;
  type.functions[0]!.name = null;
  type.interfaces[0]!.customData = analysis.customData;
  assert.match(renderTypeLibraryMembers(analysis, type), /method \?/);
  assert.match(renderTypeLibraryMembers(analysis, type), /Custom data/);
});
