import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeTypeLibraryRegistrations } from
  "../../../../../analyzers/pe/resources/type-library-registry-links.js";
import { addTypeLibraryPreview } from
  "../../../../../analyzers/pe/resources/preview/type-library.js";
import { parseRegistryScript } from
  "../../../../../analyzers/pe/resources/preview/registry-parser.js";
import type { PeResources } from "../../../../../analyzers/pe/resources/index.js";
import { createMsftLibrary } from "../../../../fixtures/type-library.js";

const libraryGuid = "11111111-1111-1111-1111-111111111111";
const classGuid = "22222222-2222-2222-2222-222222222222";
const interfaceGuid = "33333333-3333-3333-3333-333333333333";
const resources = (script: string): PeResources => {
  const preview = addTypeLibraryPreview(createMsftLibrary(), "TYPELIB", null)!.preview!;
  const analysis = preview.typeLibrary!.analysis!;
  analysis.guid = libraryGuid;
  // TYPEKIND 3 = interface, 5 = coclass.
  // https://learn.microsoft.com/en-us/windows/win32/api/oaidl/ne-oaidl-typekind
  analysis.types[0]!.kind = 3;
  analysis.types[0]!.guid = interfaceGuid;
  analysis.types[3]!.kind = 5;
  analysis.types[3]!.guid = classGuid;
  return { top: [], detail: [
    { typeName: "TYPELIB", entries: [{ id: 1, name: null, langs: [{
      lang: 1033, dataRVA: 1, size: 1, codePage: 0,
      dataFileOffset: 0, reserved: 0, ...preview
    }] }] },
    { typeName: "REGISTRY", entries: [{ id: 2, name: "sample.rgs", langs: [{
      lang: 1033, dataRVA: 2, size: 1, codePage: 0, dataFileOffset: 0, reserved: 0,
      registry: parseRegistryScript(script, [])
    }] }] }
  ] };
};

void test("links embedded RGS LIBID, CLSID, and IID keys to type library contracts", () => {
  const data = resources("HKCR { TypeLib { {11111111-1111-1111-1111-111111111111} } " +
    "CLSID { {22222222-2222-2222-2222-222222222222} } " +
    "Interface { {33333333-3333-3333-3333-333333333333} } }");
  const links = analyzeTypeLibraryRegistrations(data);
  assert.deepEqual(links.map(link => link.kind), ["LIBID", "CLSID", "IID"]);
  assert.deepEqual(links.map(link => link.name), ["Lib", "Class", "ITest"]);
  assert.ok(links.every(link => link.registryResource === "sample.rgs"));
});

void test("does not claim a registration for a different or parameterized GUID", () => {
  const data = resources("HKCR { CLSID { {AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA} %CLSID% } }");
  assert.deepEqual(analyzeTypeLibraryRegistrations(data), []);
  assert.deepEqual(analyzeTypeLibraryRegistrations(null), []);
});

void test("requires a whole GUID and the correct registry root role", () => {
  const script = "HKCR { Interface { " +
    "{33333333-3333-3333-3333-333333333333}suffix " +
    "prefix{33333333-3333-3333-3333-333333333333} " +
    "'{33333333-3333-3333-3333-333333333333' " +
    "'33333333-3333-3333-3333-333333333333}' } " +
    "AppID { {33333333-3333-3333-3333-333333333333} } }";
  assert.deepEqual(analyzeTypeLibraryRegistrations(resources(script)), []);
});

void test("distinguishes coclasses, interfaces, and dispinterfaces", () => {
  const data = resources("HKCR { Interface { {33333333-3333-3333-3333-333333333333} } " +
    "Interface { {22222222-2222-2222-2222-222222222222} } " +
    "CLSID { {22222222-2222-2222-2222-222222222222} } }");
  const types = data.detail[0]!.entries[0]!.langs[0]!.typeLibrary!.analysis!.types;
  types[0]!.kind = 4;
  types[1]!.guid = classGuid;
  types[1]!.kind = 1;
  assert.deepEqual(analyzeTypeLibraryRegistrations(data).map(link => link.kind), ["IID", "CLSID"]);
});

void test("deduplicates RGS language variants and uses fallback labels", () => {
  const data = resources("HKCR { CLSID { {22222222-2222-2222-2222-222222222222} } }");
  const libraryEntry = data.detail[0]!.entries[0]!;
  libraryEntry.langs[0]!.typeLibrary!.analysis!.name = null;
  libraryEntry.name = "Named";
  const classType = libraryEntry.langs[0]!.typeLibrary!.analysis!.types[3]!;
  classType.name = null;
  const registryEntry = data.detail[1]!.entries[0]!;
  registryEntry.name = null;
  registryEntry.langs.push({ ...registryEntry.langs[0]!, lang: 1041 });
  assert.deepEqual(analyzeTypeLibraryRegistrations(data), [{ kind: "CLSID",
    guid: classGuid, library: "Named", name: "?", registryResource: "2" }]);
  libraryEntry.name = null;
  libraryEntry.id = null;
  registryEntry.id = null;
  assert.equal(analyzeTypeLibraryRegistrations(data)[0]?.library, "?");
  assert.equal(analyzeTypeLibraryRegistrations(data)[0]?.registryResource, "?");
});

void test("does not treat a TYPELIB preview in another resource kind as embedded TYPELIB", () => {
  const data = resources("HKCR { CLSID { {22222222-2222-2222-2222-222222222222} } }");
  data.detail[0]!.typeName = "RCDATA";
  assert.deepEqual(analyzeTypeLibraryRegistrations(data), []);
});

void test("skips undecoded and unrelated resource entries", () => {
  const data = resources("HKCR { CLSID { {22222222-2222-2222-2222-222222222222} } }");
  data.detail[0]!.entries[0]!.langs[0]!.typeLibrary!.analysis!.types[3]!.guid = null;
  assert.deepEqual(analyzeTypeLibraryRegistrations(data), []);
  data.detail[0]!.typeName = "RCDATA";
  assert.deepEqual(analyzeTypeLibraryRegistrations(data), []);
  data.detail[0]!.typeName = "TYPELIB";
  delete data.detail[0]!.entries[0]!.langs[0]!.typeLibrary!.analysis;
  assert.deepEqual(analyzeTypeLibraryRegistrations(data), []);
});
