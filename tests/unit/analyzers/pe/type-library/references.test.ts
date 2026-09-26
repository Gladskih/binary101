import assert from "node:assert/strict";
import { test } from "node:test";
import { validateTypeLibraryReferences } from "../../../../../analyzers/pe/type-library/references.js";
import { addTypeLibraryPreview } from "../../../../../analyzers/pe/resources/preview/type-library.js";
import { createMsftLibrary } from "../../../../fixtures/type-library.js";

const library = () => addTypeLibraryPreview(createMsftLibrary(), "TYPELIB", null)!
  .preview!.typeLibrary!.analysis!;

void test("resolved local and imported type references do not produce warnings", () => {
  const issues: string[] = [];
  validateTypeLibraryReferences(library(), issues);
  assert.deepEqual(issues, []);
});

void test("reference validation checks aliases, members, parameters and inherited interfaces", () => {
  const analysis = library();
  analysis.types[0]!.alias = "href(900)";
  analysis.types[0]!.variables[0]!.type = "href(900)";
  analysis.types[0]!.functions[0]!.parameters[0]!.type = "href(13)";
  analysis.types[0]!.interfaces[0]!.reference = -1;
  analysis.importedTypes[0]!.libraryOffset = 999;
  const issues: string[] = [];
  validateTypeLibraryReferences(analysis, issues);
  assert.deepEqual(issues, ["TYPELIB imported type refers to a missing library.",
    "TYPELIB type reference -1 is unresolved.", "TYPELIB type reference 900 is unresolved.",
    "TYPELIB type reference 13 is unresolved."]);
});

void test("reference validation merges diagnostics across repeated checks", () => {
  const analysis = library();
  analysis.types[0]!.alias = "href(400) href(500)";
  const issues = ["Existing warning"];
  validateTypeLibraryReferences(analysis, issues);
  validateTypeLibraryReferences(analysis, issues);
  assert.deepEqual(issues, ["Existing warning", "TYPELIB type reference 400 is unresolved.",
    "TYPELIB type reference 500 is unresolved."]);
});
