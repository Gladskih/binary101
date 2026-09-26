import assert from "node:assert/strict";
import { test } from "node:test";
import {
  formatLibraryValue, formatTypeLibraryFlags, libraryVersion, renderCustomData,
  renderTypeLibraryTable, resolveTypeLibraryDescription, resolveTypeLibraryReference, typeKindName
} from "../../../../renderers/pe/type-library-tables.js";
import { addTypeLibraryPreview } from "../../../../analyzers/pe/resources/preview/type-library.js";
import { createMsftLibrary } from "../../../fixtures/type-library.js";

const library = () => addTypeLibraryPreview(createMsftLibrary(), "TYPELIB", null)!
  .preview!.typeLibrary!.analysis!;

void test("tables format type kinds, versions, flags and variant values", () => {
  assert.equal(typeKindName(3), "interface");
  assert.equal(typeKindName(9), "TKIND(9)");
  assert.equal(libraryVersion(0x20001), "1.2");
  assert.equal(formatTypeLibraryFlags(3, ["in", "out"]), "in, out (0x3)");
  assert.equal(formatTypeLibraryFlags(0, ["in"]), "(0x0)");
  assert.equal(formatLibraryValue(null), "—");
  assert.equal(formatLibraryValue({ type: 8, value: "ok" }), "BSTR: ok");
  assert.equal(formatLibraryValue({ type: 8, value: null }), "BSTR: null / unavailable");
});

void test("dense tables have semantic captions, numeric alignment and escaped cells", () => {
  const html = renderTypeLibraryTable("<caption>", ["<header>"], [[null, 42, "<cell>"]]);
  assert.match(html, /&lt;caption>/);
  assert.match(html, /scope="col"/);
  assert.match(html, /&lt;header>/);
  assert.match(html, /class="peNumeric">42/);
  assert.match(html, /&lt;cell>/);
  assert.equal(renderTypeLibraryTable("empty", [], []), "");
  assert.match(renderCustomData(library().customData), /long: -123/);
});

void test("references resolve local types and imported library/type identity", () => {
  const analysis = library();
  assert.equal(resolveTypeLibraryReference(analysis, 0), "ITest");
  assert.match(resolveTypeLibraryReference(analysis, 1), /^a.tlb:/);
  assert.equal(resolveTypeLibraryReference(analysis, 400), "href(400)");
  assert.equal(resolveTypeLibraryReference(analysis, 13), "href(13)");
  assert.equal(resolveTypeLibraryDescription(analysis, "href(0)*"), "ITest*");
  analysis.imports = [];
  analysis.importedTypes[0]!.identifier = null;
  assert.equal(resolveTypeLibraryReference(analysis, 1), "import: unknown type");
});
