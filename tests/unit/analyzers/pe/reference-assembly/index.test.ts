"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  detectPeReferenceAssemblySubtypeFromClr,
  isPeReferenceAssembly
} from "../../../../../analyzers/pe/reference-assembly.js";
import type { PeClrHeader, PeClrMetadataTables } from "../../../../../analyzers/pe/clr/types.js";

// ECMA-335 II.22.2 assigns 0x20 to the Assembly metadata table.
const TABLE_ASSEMBLY = 0x20;
// ECMA-335 II.22.37 assigns 0x02 to the TypeDef metadata table.
const TABLE_TYPE_DEF = 0x02;
const REFERENCE_ASSEMBLY_ATTRIBUTE =
  "System.Runtime.CompilerServices.ReferenceAssemblyAttribute";

const createTables = (
  tableId: number,
  attributeType = REFERENCE_ASSEMBLY_ATTRIBUTE
): PeClrMetadataTables => ({
  streamName: "#~",
  majorVersion: 2,
  minorVersion: 0,
  heapSizes: 0,
  largestRidLog2: 0,
  validMask: "0x0000000100000000",
  sortedMask: "0x0000000000000000",
  heapIndexSizes: { string: 2, guid: 2, blob: 2 },
  rowCounts: [],
  modules: [],
  assembly: null,
  assemblyRefs: [],
  typeRefs: [],
  typeDefs: [],
  methodDefs: [],
  parameters: [],
  memberRefs: [],
  moduleRefs: [],
  implMaps: [],
  files: [],
  exportedTypes: [],
  manifestResources: [],
  customAttributes: [{
    row: 1,
    parent: { table: "Assembly", tableId, row: 1, raw: 14 << 5, valid: true },
    parentName: "ReferenceOnly",
    constructor: null,
    constructorName: ".ctor",
    attributeType,
    valueBlobIndex: 1,
    fixedArguments: [],
    namedArguments: []
  }]
});

const createClr = (tables?: PeClrMetadataTables): PeClrHeader => ({
  cb: 0,
  MajorRuntimeVersion: 0,
  MinorRuntimeVersion: 0,
  MetaDataRVA: 0,
  MetaDataSize: 0,
  Flags: 0,
  EntryPointToken: 0,
  ResourcesRVA: 0,
  ResourcesSize: 0,
  StrongNameSignatureRVA: 0,
  StrongNameSignatureSize: 0,
  CodeManagerTableRVA: 0,
  CodeManagerTableSize: 0,
  VTableFixupsRVA: 0,
  VTableFixupsSize: 0,
  ExportAddressTableJumpsRVA: 0,
  ExportAddressTableJumpsSize: 0,
  ManagedNativeHeaderRVA: 0,
  ManagedNativeHeaderSize: 0,
  meta: tables ? { streams: [], tables } : { streams: [] }
});

void test("detectPeReferenceAssemblySubtypeFromClr detects assembly-level ReferenceAssemblyAttribute", () => {
  assert.equal(
    detectPeReferenceAssemblySubtypeFromClr(createClr(createTables(TABLE_ASSEMBLY))),
    "dotnet-reference-assembly"
  );
});

void test("detectPeReferenceAssemblySubtypeFromClr rejects unrelated or non-assembly attributes", () => {
  assert.equal(detectPeReferenceAssemblySubtypeFromClr(createClr()), null);
  assert.equal(
    detectPeReferenceAssemblySubtypeFromClr(createClr(createTables(TABLE_TYPE_DEF))),
    null
  );
  assert.equal(
    detectPeReferenceAssemblySubtypeFromClr(createClr(createTables(TABLE_ASSEMBLY, "Example.Attribute"))),
    null
  );
});

void test("isPeReferenceAssembly checks the parsed PE subtype field", () => {
  assert.equal(isPeReferenceAssembly({ subtype: "dotnet-reference-assembly" }), true);
  assert.equal(isPeReferenceAssembly({ subtype: "winmd" }), false);
  assert.equal(isPeReferenceAssembly({}), false);
});
