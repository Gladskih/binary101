"use strict";

import type { PeClrAssemblyRefInfo, PeClrMetadataTables, PeClrMetadataIndex }
  from "../../analyzers/pe/clr/types.js";
import { registerClrResolutionSession } from "../../analyzers/pe/clr/metadata-resolution-session.js";

export const clrIndex = (tableId: number, row = 1): PeClrMetadataIndex =>
  ({ table: "fixture", tableId, row, raw: row, valid: true });

export const clrAssemblyReference = (name = "Library"): PeClrAssemblyRefInfo => ({
  row: 1, name, version: "1.2.3.4", culture: "", flags: 0, publicKeyOrToken: [], hashValue: []
});

export const clrResolutionFixture = (name = "Application", enums = new Map<string, string>()): PeClrMetadataTables => {
  const tables: PeClrMetadataTables = {
    streamName: "#~", majorVersion: 2, minorVersion: 0, heapSizes: 0, largestRidLog2: 0,
    validMask: "0", sortedMask: "0", heapIndexSizes: { string: 2, guid: 2, blob: 2 }, rowCounts: [],
    assembly: { row: 1, name, culture: "", version: "1.2.3.4", hashAlgorithm: 0, flags: 0, publicKey: [] },
    modules: [], assemblyRefs: [], typeRefs: [], typeDefs: [...enums.keys()].map((fullName, index) => ({
      row: index + 1, name: fullName, namespace: "", fullName, flags: 0, extends: clrIndex(1),
      fieldStart: 1, fieldEnd: 1, methodStart: 1, methodEnd: 0
    })), fields: [], methodDefs: [], parameters: [], memberRefs: [], moduleRefs: [],
    implMaps: [], files: [], exportedTypes: [], manifestResources: [], customAttributes: []
  };
  registerClrResolutionSession(tables, { enumTypes: enums, resolve: enumTypes => ({ ...tables,
    customAttributes: tables.customAttributes.map(attribute => ({ ...attribute,
      fixedArguments: attribute.fixedArguments.map(argument => ({ ...argument,
        value: enumTypes.get(argument.type!) ?? null })) })) }) });
  return tables;
};

export const requestEnumTypes = (tables: PeClrMetadataTables, names: string[]): void => {
  tables.customAttributes = [{ row: 1, parent: clrIndex(32), parentName: "Application", constructor: clrIndex(10),
    constructorName: ".ctor", attributeType: "Demo.Attribute", valueBlobIndex: 1,
    fixedArguments: names.map(type => ({ type, value: null })), namedArguments: [] }];
};
