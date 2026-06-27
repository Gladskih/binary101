"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveMetadataIndexName } from "../../../../../../analyzers/pe/clr/metadata-name-resolver.js";
import type {
  PeClrAssemblyInfo,
  PeClrAssemblyRefInfo,
  PeClrMetadataIndex,
  PeClrTypeDefinitionInfo,
  PeClrTypeReferenceInfo
} from "../../../../../../analyzers/pe/clr/types.js";

// CLR metadata table ids are defined by ECMA-335 II.22 metadata table numbering.
const ASSEMBLY_TABLE_ID = 0x20;
const ASSEMBLY_REF_TABLE_ID = 0x23;
const TYPE_REF_TABLE_ID = 0x01;
const TYPE_DEF_TABLE_ID = 0x02;
const UNKNOWN_TABLE_ID = ASSEMBLY_TABLE_ID + ASSEMBLY_REF_TABLE_ID + TYPE_DEF_TABLE_ID + TYPE_REF_TABLE_ID;
const generatedName = (index: number): string => `name-${index.toString(36)}`;

const index = (table: string, tableId: number, row: number): PeClrMetadataIndex => ({
  table,
  tableId,
  row,
  raw: row,
  valid: true
});

const assembly: PeClrAssemblyInfo = {
  row: 1,
  name: generatedName(0),
  culture: "",
  version: generatedName(1),
  hashAlgorithm: 0,
  flags: 0,
  publicKey: []
};

const assemblyRefs: PeClrAssemblyRefInfo[] = [{
  row: 1,
  name: generatedName(2),
  culture: "",
  version: generatedName(3),
  flags: 0,
  publicKeyOrTokenSize: 8,
  hashValueSize: 0
}];

const typeRefs: PeClrTypeReferenceInfo[] = [{
  row: 1,
  name: generatedName(4),
  namespace: generatedName(5),
  fullName: generatedName(6),
  resolutionScope: index("AssemblyRef", ASSEMBLY_REF_TABLE_ID, 1)
}];

const typeDefs: PeClrTypeDefinitionInfo[] = [{
  row: 1,
  name: generatedName(7),
  namespace: generatedName(8),
  fullName: generatedName(9),
  flags: 0,
  extends: index("TypeRef", TYPE_REF_TABLE_ID, 1),
  fieldStart: 1,
  fieldEnd: null,
  methodStart: 1,
  methodEnd: null
}];

void test("resolveMetadataIndexName resolves common CLR metadata index targets", () => {
  const resolve = (metadataIndex: PeClrMetadataIndex): string | null =>
    resolveMetadataIndexName(metadataIndex, [], assembly, assemblyRefs, typeRefs, typeDefs, [], []);

  assert.strictEqual(resolve(index("Assembly", ASSEMBLY_TABLE_ID, 1)), assembly.name);
  assert.strictEqual(resolve(index("AssemblyRef", ASSEMBLY_REF_TABLE_ID, 1)), assemblyRefs[0]?.name);
  assert.strictEqual(resolve(index("TypeRef", TYPE_REF_TABLE_ID, 1)), typeRefs[0]?.fullName);
  assert.strictEqual(resolve(index("TypeDef", TYPE_DEF_TABLE_ID, 1)), typeDefs[0]?.fullName);
  assert.strictEqual(resolve(index("TypeDef", TYPE_DEF_TABLE_ID, 0)), null);
  assert.strictEqual(resolve(index("NoSuchTable", UNKNOWN_TABLE_ID, 1)), null);
});
