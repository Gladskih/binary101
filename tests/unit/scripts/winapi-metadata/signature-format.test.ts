"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeClrMetadataTables, PeClrMethodDefinitionInfo } from "../../../../analyzers/pe/clr/types.js";
import {
  buildWinapiParameters,
  formatWinapiSignature,
  resolveSignatureType
} from "../../../../scripts/winapi-metadata/signature-format.js";

const PARAM_IN_FLAG = 0x0001;
const PARAM_OUT_FLAG = 0x0002;

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
  typeDefs: [{
    row: 1,
    name: "PWSTR",
    namespace: "Windows.Win32.Foundation",
    fullName: "Windows.Win32.Foundation.PWSTR",
    flags: 0,
    extends: { table: "null", tableId: -1, row: 0, raw: 0, valid: true },
    fieldStart: 1,
    fieldEnd: 1,
    methodStart: 1,
    methodEnd: null
  }],
  fields: [{
    row: 1,
    name: "Value",
    flags: 0,
    signatureBlobIndex: 1,
    signature: {
      callingConvention: 0x06,
      parameterCount: 0,
      returnType: "u2*",
      parameterTypes: []
    }
  }],
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
    { row: 1, flags: PARAM_IN_FLAG, sequence: 1, name: "flags" },
    { row: 2, flags: PARAM_IN_FLAG | PARAM_OUT_FLAG, sequence: 2, name: "name" }
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

void test("x86 stack byte metadata resolves WinMD value-type wrappers", () => {
  const parameters = buildWinapiParameters(method(), tables());

  assert.deepStrictEqual(parameters.map(parameter => parameter.x86StackBytes), [4, 4]);
  assert.deepStrictEqual(parameters.map(parameter => parameter.direction), ["in", "inout"]);
});
