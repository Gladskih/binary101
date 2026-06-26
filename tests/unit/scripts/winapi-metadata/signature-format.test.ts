"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeClrMetadataTables, PeClrMethodDefinitionInfo } from "../../../../analyzers/pe/clr/types.js";
import {
  buildWinapiParameters,
  formatWinapiSignature,
  resolveSignatureType,
  x86StackBytesForParameters
} from "../../../../scripts/winapi-metadata/signature-format.js";

const tables = (): PeClrMetadataTables => ({
  streamName: "#~",
  majorVersion: 2,
  minorVersion: 0,
  heapSizes: 0,
  largestRidLog2: 0,
  validMask: "0x0000000000000000",
  sortedMask: "0x0000000000000000",
  heapIndexSizes: { string: 2, guid: 2, blob: 2 },
  rowCounts: [],
  modules: [],
  assembly: null,
  assemblyRefs: [],
  typeRefs: [{
    row: 1,
    name: "PWSTR",
    namespace: "Windows.Win32.Foundation",
    resolutionScope: { table: "null", tableId: -1, row: 0, raw: 0, valid: true },
    fullName: "Windows.Win32.Foundation.PWSTR"
  }],
  typeDefs: [],
  methodDefs: [],
  parameters: [],
  memberRefs: [],
  moduleRefs: [],
  implMaps: [],
  files: [],
  exportedTypes: [],
  manifestResources: [],
  customAttributes: []
});

const method = (): PeClrMethodDefinitionInfo => ({
  row: 1,
  name: "ExampleW",
  ownerType: "Windows.Win32.Tests.Apis",
  rva: 0,
  implFlags: 0,
  flags: 0,
  signatureBlobIndex: 1,
  signature: {
    callingConvention: 0,
    parameterCount: 2,
    returnType: "void",
    parameterTypes: ["u4", "valuetype TypeRef#1"]
  },
  parameters: [
    { row: 1, flags: 0, sequence: 1, name: "flags" },
    { row: 2, flags: 0, sequence: 2, name: "name" }
  ]
});

void test("signature formatting resolves metadata type references and parameter names", () => {
  const metadataTables = tables();

  assert.equal(resolveSignatureType("valuetype TypeRef#1", metadataTables), "Windows.Win32.Foundation.PWSTR");
  assert.equal(
    formatWinapiSignature(method(), "ExampleW", metadataTables),
    "void ExampleW(u4 flags, Windows.Win32.Foundation.PWSTR name)"
  );
});

void test("x86 stack byte metadata is conservative for unresolved value types", () => {
  const parameters = buildWinapiParameters(method(), tables());

  assert.deepStrictEqual(parameters.map(parameter => parameter.x86StackBytes), [4, null]);
  assert.equal(x86StackBytesForParameters(parameters), null);
});
