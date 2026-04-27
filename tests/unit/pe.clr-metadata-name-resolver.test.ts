"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveMetadataIndexName } from "../../analyzers/pe/clr/metadata-name-resolver.js";
import type {
  PeClrAssemblyInfo,
  PeClrAssemblyRefInfo,
  PeClrMetadataIndex,
  PeClrTypeDefinitionInfo,
  PeClrTypeReferenceInfo
} from "../../analyzers/pe/clr/types.js";

const index = (table: string, tableId: number, row: number): PeClrMetadataIndex => ({
  table,
  tableId,
  row,
  raw: row,
  valid: true
});

const assembly: PeClrAssemblyInfo = {
  row: 1,
  name: "App",
  culture: "",
  version: "1.0.0.0",
  hashAlgorithm: 0,
  flags: 0,
  publicKeySize: 0
};

const assemblyRefs: PeClrAssemblyRefInfo[] = [{
  row: 1,
  name: "System.Runtime",
  culture: "",
  version: "8.0.0.0",
  flags: 0,
  publicKeyOrTokenSize: 8,
  hashValueSize: 0
}];

const typeRefs: PeClrTypeReferenceInfo[] = [{
  row: 1,
  name: "Object",
  namespace: "System",
  fullName: "System.Object",
  resolutionScope: index("AssemblyRef", 0x23, 1)
}];

const typeDefs: PeClrTypeDefinitionInfo[] = [{
  row: 1,
  name: "Program",
  namespace: "App",
  fullName: "App.Program",
  flags: 0,
  extends: index("TypeRef", 0x01, 1),
  fieldStart: 1,
  methodStart: 1,
  methodEnd: null
}];

void test("resolveMetadataIndexName resolves common CLR metadata index targets", () => {
  const resolve = (metadataIndex: PeClrMetadataIndex): string | null =>
    resolveMetadataIndexName(metadataIndex, [], assembly, assemblyRefs, typeRefs, typeDefs, [], []);

  assert.strictEqual(resolve(index("Assembly", 0x20, 1)), "App");
  assert.strictEqual(resolve(index("AssemblyRef", 0x23, 1)), "System.Runtime");
  assert.strictEqual(resolve(index("TypeRef", 0x01, 1)), "System.Object");
  assert.strictEqual(resolve(index("TypeDef", 0x02, 1)), "App.Program");
  assert.strictEqual(resolve(index("TypeDef", 0x02, 0)), null);
  assert.strictEqual(resolve(index("NoSuchTable", 0x7e, 1)), null);
});
