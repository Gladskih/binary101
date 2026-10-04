"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveClrMetadataDependencies } from "../../../../../../analyzers/pe/clr/metadata-dependencies.js";
import { clrAssemblyReference, clrIndex, clrResolutionFixture, requestEnumTypes }
  from "../../../../../helpers/clr-resolution-fixture.js";

const referenceApplication = () => {
  const tables = clrResolutionFixture();
  tables.assemblyRefs = [clrAssemblyReference()];
  tables.typeRefs = [{ row: 1, name: "Mode", namespace: "Demo", fullName: "Demo.Mode", resolutionScope: clrIndex(35) }];
  requestEnumTypes(tables, ["TypeRef#1 (Demo.Mode)"]);
  return tables;
};
const enumLibrary = () => clrResolutionFixture("Library", new Map([["Demo.Mode", "u1"]]));
const decodedTypes = (tables: ReturnType<typeof clrResolutionFixture>) =>
  tables.customAttributes[0]!.fixedArguments.map(argument => argument.value);

void test("resolves a referenced enum only from the matching assembly", () => {
  const source = referenceApplication();
  source.typeDefs = enumLibrary().typeDefs;
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [enumLibrary()])), ["u1"]);
  assert.equal(resolveClrMetadataDependencies(source, [enumLibrary()]).issues, undefined);
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [])), [null]);
  assert.match(resolveClrMetadataDependencies(source, []).issues!.join(";"), /unavailable/);
});

void test("keeps local, nested and assembly-qualified identities distinct", () => {
  const source = referenceApplication();
  source.typeRefs.push({ ...source.typeRefs[0]!, row: 2, fullName: "Demo.Mode+Nested", resolutionScope: clrIndex(1) });
  const library = clrResolutionFixture("Library", new Map([["Demo.Mode", "u1"], ["Demo.Mode+Nested", "i8"]]));
  requestEnumTypes(source, ["TypeRef#2 (Demo.Mode+Nested)", "Demo.Mode, Library", "Demo.Mode"]);
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [library])), ["i8", "u1", null]);
});

void test("follows a validated type forwarder without assuming enum width", () => {
  const facade = clrResolutionFixture("Facade");
  facade.assemblyRefs = [clrAssemblyReference()];
  facade.exportedTypes = [{ row: 1, name: "Mode", namespace: "Demo", fullName: "Demo.Mode",
    flags: 0x00200000, typeDefId: 0, implementation: clrIndex(35) }]; // ECMA-335 II.6.8 Forwarder.
  const source = referenceApplication();
  source.assemblyRefs[0] = clrAssemblyReference("Facade");
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [facade, enumLibrary()])), ["u1"]);
  facade.exportedTypes[0]!.flags = 0;
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [facade, enumLibrary()])), [null]);
});

void test("detects forwarding cycles and ambiguous definitions", () => {
  const source = referenceApplication();
  const library = clrResolutionFixture("Library");
  library.assemblyRefs = [clrAssemblyReference()];
  library.exportedTypes = [{ row: 1, name: "Mode", namespace: "Demo", fullName: "Demo.Mode",
    flags: 0x00200000, typeDefId: 0, implementation: clrIndex(35) }];
  assert.match(resolveClrMetadataDependencies(source, [library]).issues!.join(";"), /forwarding cycle/);
  const duplicate = enumLibrary();
  duplicate.typeDefs.push({ ...duplicate.typeDefs[0]!, row: 2 });
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [duplicate])), [null]);
});

void test("allows a later dependency selection to repair previous missing dependencies", () => {
  const source = referenceApplication();
  const unresolved = resolveClrMetadataDependencies(source, []);
  const resolved = resolveClrMetadataDependencies(unresolved, [enumLibrary()]);
  assert.deepEqual(decodedTypes(resolved), ["u1"]);
  assert.equal(resolved.issues, undefined);
  assert.deepEqual(decodedTypes(source), [null]);
});

void test("reports unavailable decoding inputs and malformed serialized names", () => {
  assert.match(resolveClrMetadataDependencies({ ...clrResolutionFixture() }, []).issues!.join(";"), /decoding inputs/);
  const source = clrResolutionFixture();
  requestEnumTypes(source, ["Bad[]", "Bad[]"]);
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [])), [null, null]);
  assert.equal(resolveClrMetadataDependencies(source, []).issues!.length, 1);
});

for (const scope of [clrIndex(1), clrIndex(26), clrIndex(35, 2), { ...clrIndex(35), valid: false }]) {
  void test(`rejects unusable TypeRef scope ${JSON.stringify(scope)}`, () => {
    const source = referenceApplication();
    source.typeRefs[0]!.resolutionScope = scope;
    assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [enumLibrary()])), [null]);
  });
}

void test("resolves Module scope locally and rejects mismatched reference labels", () => {
  const source = clrResolutionFixture("Library", new Map([["Demo.Mode", "i2"]]));
  source.typeRefs = [{ row: 1, name: "Mode", namespace: "Demo", fullName: "Demo.Mode", resolutionScope: clrIndex(0) }];
  requestEnumTypes(source, ["TypeRef#1 (Demo.Mode)", "TypeRef#1 (Other.Mode)", "TypeRef#2 (Demo.Mode)"]);
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [])), ["i2", null, null]);
});

void test("keeps literal plus signs distinct from nested types when resolving serialized enums", () => {
  const source = clrResolutionFixture();
  const library = clrResolutionFixture("Library", new Map([["Demo.Outer+Mode", "u1"], ["Demo.Outer\\+Mode", "i8"]]));
  requestEnumTypes(source, ["Demo.Outer+Mode, Library", "Demo.Outer\\+Mode, Library"]);
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [library])), ["u1", "i8"]);
});

void test("resolves a null TypeRef scope through its exported type entry", () => {
  const source = referenceApplication();
  source.typeRefs[0]!.resolutionScope = { table: "null", tableId: -1, row: 0, raw: 0, valid: true };
  source.exportedTypes = [{ row: 1, name: "Mode", namespace: "Demo", fullName: "Demo.Mode",
    flags: 0x00200000, typeDefId: 0, implementation: clrIndex(35) }];
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [enumLibrary()])), ["u1"]);
});

void test("resolves referenced identifiers containing significant newline characters", () => {
  const source = referenceApplication();
  source.typeRefs[0]!.fullName = "Demo.Line\nMode";
  requestEnumTypes(source, ["TypeRef#1 (Demo.Line\nMode)"]);
  const library = clrResolutionFixture("Library", new Map([["Demo.Line\nMode", "u2"]]));
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [library])), ["u2"]);
});

void test("matches the entire reference label and supports multiple digit row numbers", () => {
  const source = referenceApplication();
  source.typeRefs = Array.from({ length: 12 }, (_, index) => ({ ...source.typeRefs[0]!, row: index + 1 }));
  requestEnumTypes(source, ["TypeRef#12 (Demo.Mode)", "prefix TypeRef#12 (Demo.Mode)",
    "TypeRef#12 (Demo.Mode)suffix"]);
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [enumLibrary()])), ["u1", null, null]);
});

void test("preserves existing diagnostics when resolution inputs are unavailable", () => {
  const source = { ...clrResolutionFixture(), issues: ["Invalid metadata stream."] };
  assert.deepEqual(resolveClrMetadataDependencies(source, []).issues,
    ["Invalid metadata stream.", "CLR decoding inputs are unavailable."]);
});

void test("follows nested exported types and rejects ambiguous or invalid destinations", () => {
  const source = referenceApplication();
  source.assemblyRefs[0] = clrAssemblyReference("Facade");
  source.typeRefs[0]!.fullName = "Demo.Outer+Mode";
  requestEnumTypes(source, ["TypeRef#1 (Demo.Outer+Mode)"]);
  const facade = clrResolutionFixture("Facade");
  facade.assemblyRefs = [clrAssemblyReference()];
  facade.exportedTypes = [{ row: 1, name: "Outer", namespace: "Demo", fullName: "Demo.Outer",
    flags: 0x00200000, typeDefId: 0, implementation: clrIndex(35) },
  { row: 2, name: "Mode", namespace: "", fullName: "Demo.Outer+Mode",
    flags: 0, typeDefId: 0, implementation: clrIndex(39) }]; // ECMA-335 II.22.14 nested ExportedType.
  const library = clrResolutionFixture("Library", new Map([["Demo.Outer+Mode", "i8"]]));
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [facade, library])), ["i8"]);
  facade.exportedTypes[0]!.implementation = clrIndex(38);
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [facade, library])), [null]);
  facade.exportedTypes[0]!.implementation = clrIndex(35);
  facade.exportedTypes.push({ ...facade.exportedTypes[1]!, row: 3 });
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [facade, library])), [null]);
});

void test("keeps a null-scope reference unresolved without an exported destination", () => {
  const source = referenceApplication();
  source.typeRefs[0]!.resolutionScope = { table: "null", tableId: -1, row: 0, raw: 0, valid: true };
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [enumLibrary()])), [null]);
});

void test("reports unavailable serialized assembly dependencies", () => {
  const source = clrResolutionFixture();
  requestEnumTypes(source, ["Demo.Mode, Missing"]);
  const resolved = resolveClrMetadataDependencies(source, []);
  assert.deepEqual(decodedTypes(resolved), [null]);
  assert.deepEqual(resolved.issues, ["Assembly dependency missing is unavailable or mismatched."]);
});

void test("rejects cyclic enclosing exported type chains", () => {
  const source = referenceApplication();
  const library = clrResolutionFixture("Library");
  library.exportedTypes = [{ row: 1, name: "Mode", namespace: "Demo", fullName: "Demo.Mode",
    flags: 0x00200000, typeDefId: 0, implementation: clrIndex(39) }];
  assert.deepEqual(decodedTypes(resolveClrMetadataDependencies(source, [library])), [null]);
});

void test("resolves local enums in a valid module without an Assembly row", () => {
  const source = clrResolutionFixture("Module", new Map([["Demo.Mode", "i2"]]));
  source.assembly = null; // ECMA-335 II.22.2 permits zero Assembly rows (a netmodule).
  requestEnumTypes(source, ["Demo.Mode"]);
  const resolved = resolveClrMetadataDependencies(source, []);
  assert.deepEqual(decodedTypes(resolved), ["i2"]);
  assert.equal(resolved.issues, undefined);
});
