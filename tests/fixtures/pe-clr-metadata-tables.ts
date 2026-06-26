"use strict";

import type {
  PeClrMetadataIndex,
  PeClrMetadataTables,
  PeClrMethodDefinitionInfo,
  PeClrParameterInfo
} from "../../analyzers/pe/clr/types.js";

const TYPE_REF_TABLE_ID = 0x01; // ECMA-335 II.22 TypeRef table.
const TYPE_DEF_TABLE_ID = 0x02; // ECMA-335 II.22 TypeDef table.
const METHOD_PUBLIC_FLAG = 0x0006; // ECMA-335 II.23.1.10 MethodAttributes.Public.
const PARAM_IN_FLAG = 0x0001; // ECMA-335 II.23.1.13 ParamAttributes.In.
const PARAM_OUT_FLAG = 0x0002; // ECMA-335 II.23.1.13 ParamAttributes.Out.

const nullTypeRefIndex = (): PeClrMetadataIndex => ({
  table: "TypeRef",
  tableId: TYPE_REF_TABLE_ID,
  row: 0,
  raw: 0,
  valid: false
});

const parameter = (
  row: number,
  sequence: number,
  name: string,
  flags = 0
): PeClrParameterInfo => ({ row, sequence, name, flags });

const method = (
  row: number,
  name: string,
  ownerType: string | null,
  signature: PeClrMethodDefinitionInfo["signature"],
  parameters: PeClrParameterInfo[]
): PeClrMethodDefinitionInfo => ({
  row,
  name,
  ownerType,
  rva: 0x1233 + row,
  implFlags: 0,
  flags: METHOD_PUBLIC_FLAG,
  signatureBlobIndex: row,
  ...(signature ? { signature } : {}),
  ...(parameters.length ? { parameters } : {})
});

export const createClrMetadataTablesWithParameterNames = (): PeClrMetadataTables => {
  const returnValue = parameter(1, 0, "returnValue", PARAM_OUT_FLAG);
  const source = parameter(2, 1, "source", PARAM_IN_FLAG);
  const length = parameter(3, 2, "length");
  const value = parameter(4, 1, "value");
  return {
    streamName: "#~",
    majorVersion: 2,
    minorVersion: 0,
    heapSizes: 0,
    largestRidLog2: 0,
    validMask: "0x0000000000000000",
    sortedMask: "0x0000000000000000",
    heapIndexSizes: { string: 2, guid: 2, blob: 2 },
    rowCounts: [{ tableId: TYPE_DEF_TABLE_ID, name: "TypeDef", rows: 1, known: true, sorted: false }],
    modules: [],
    assembly: null,
    assemblyRefs: [],
    typeRefs: [],
    typeDefs: [{
      row: 1,
      name: "Buffer",
      namespace: "Demo",
      fullName: "Demo.Buffer",
      flags: 0,
      extends: nullTypeRefIndex(),
      fieldStart: 0,
      methodStart: 1,
      methodEnd: 3
    }],
    methodDefs: [
      method(1, "Copy", "Demo.Buffer", {
        callingConvention: 0,
        parameterCount: 2,
        returnType: "bool",
        parameterTypes: ["string", "i4"]
      }, [returnValue, source, length]),
      method(2, "Describe", "Demo.Buffer", {
        callingConvention: 0,
        parameterCount: 1,
        returnType: null,
        parameterTypes: [null]
      }, [value]),
      method(3, "NoSignature", null, undefined, [])
    ],
    parameters: [returnValue, source, length, value],
    memberRefs: [],
    moduleRefs: [],
    implMaps: [],
    files: [],
    exportedTypes: [],
    manifestResources: [],
    customAttributes: []
  };
};
