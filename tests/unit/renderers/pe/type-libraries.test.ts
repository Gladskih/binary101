import assert from "node:assert/strict";
import { test } from "node:test";
import { renderTypeLibraries } from "../../../../renderers/pe/type-libraries.js";
import { addTypeLibraryPreview } from "../../../../analyzers/pe/resources/preview/type-library.js";
import type { PeResources } from "../../../../analyzers/pe/resources/index.js";
import { createMsftLibrary } from "../../../fixtures/type-library.js";

const resources = (): PeResources => ({ top: [], detail: [{ typeName: "TYPELIB", entries: [{
  id: 1, name: null, langs: [{ lang: 1033, dataRVA: 0, size: 0, codePage: 0,
    dataFileOffset: null, reserved: 0,
    ...addTypeLibraryPreview(createMsftLibrary(), "TYPELIB", null)!.preview }]
}] }] });

void test("deep type library section is compatible with lazy section mounting", () => {
  const html = renderTypeLibraries(resources());
  assert.match(html, /class="peSection"/);
  assert.match(html, /class="peSectionBody"/);
  assert.match(html, /Imported libraries/);
  assert.match(html, /Alias target/);
  assert.match(html, /HRESULT/);
  assert.match(html, /Binary header and segment directory/);
});

void test("type library section handles warnings, unparsed entries and format summaries", () => {
  const data = resources();
  const entry = data.detail[0]!.entries[0]!;
  entry.name = "<library>";
  entry.langs[0]!.previewIssues = ["<warning>"];
  entry.langs.push({ lang: null, dataRVA: 0, size: 0, codePage: 0, dataFileOffset: null, reserved: 0 });
  entry.langs.push({ lang: null, dataRVA: 0, size: 0, codePage: 0,
    dataFileOffset: null, reserved: 0, typeLibrary: {
    format: "placeholder", headerFields: [], segments: []
  } });
  assert.match(renderTypeLibraries(data), /&lt;library>/);
  assert.match(renderTypeLibraries(data), /&lt;warning>/);
  assert.match(renderTypeLibraries(data), /could not be decoded/);
  assert.match(renderTypeLibraries(data), /placeholder type library/);
  assert.equal(renderTypeLibraries(undefined), "");
  assert.equal(renderTypeLibraries(null), "");
  assert.equal(renderTypeLibraries({ top: [], detail: [] }), "");
});

void test("section renders unknown type kinds and absent names without throwing", () => {
  const data = resources();
  const type = data.detail[0]!.entries[0]!.langs[0]!.typeLibrary!.analysis!.types[0]!;
  type.name = null;
  type.kind = 99;
  assert.match(renderTypeLibraries(data), /TKIND\(99\) \?/);
});

void test("SLTG imported type kinds are shown as unavailable rather than guessed as enum", () => {
  const data = resources();
  data.detail[0]!.entries[0]!.langs[0]!.typeLibrary!.analysis!.importedTypes[0]!.flags = null;
  assert.match(renderTypeLibraries(data), /Not recorded/);
});

void test("shows explicit module export matches and unresolved entries", () => {
  const html = renderTypeLibraries(resources(), { matches: [
    { ordinal: 7, library: "Lib", module: "Module", function: "Run", entry: "RunExport" }
  ], warnings: ["Missing <entry>"] });
  assert.match(html, /DLL entry cross-check/);
  assert.match(html, /Module\.Run/);
  assert.match(html, /RunExport/);
  assert.match(html, /Missing &lt;entry>/);
});

void test("shows RGS registrations linked by exact LIBID, CLSID, and IID", () => {
  const html = renderTypeLibraries(resources(), { matches: [], warnings: [] }, [
    { kind: "CLSID", guid: "12345678-1234-1234-1234-123456789abc", library: "Lib",
      name: "Class", registryResource: "test<.rgs" }
  ]);
  assert.match(html, /Embedded COM registrations/);
  assert.match(html, /CLSID/);
  assert.match(html, /test&lt;\.rgs/);
});
