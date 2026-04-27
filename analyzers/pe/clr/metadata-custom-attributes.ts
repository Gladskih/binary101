"use strict";

import type {
  PeClrAssemblyInfo,
  PeClrAssemblyRefInfo,
  PeClrCustomAttributeInfo,
  PeClrMemberReferenceInfo,
  PeClrMethodDefinitionInfo,
  PeClrModuleInfo,
  PeClrModuleReferenceInfo,
  PeClrTypeDefinitionInfo,
  PeClrTypeReferenceInfo
} from "./types.js";
import type { ClrHeapReaders } from "./metadata-heaps.js";
import type { ClrMetadataRow } from "./metadata-table-reader.js";
import { decodeCustomAttributeValue } from "./metadata-attributes.js";
import { TABLE_MEMBER_REF, TABLE_METHOD_DEF } from "./metadata-schema.js";
import { resolveMetadataIndexName } from "./metadata-name-resolver.js";

const cellNumber = (row: ClrMetadataRow, name: string): number =>
  typeof row[name] === "number" ? row[name] : 0;

const cellIndex = (row: ClrMetadataRow, name: string): PeClrCustomAttributeInfo["parent"] =>
  typeof row[name] === "object"
    ? row[name] as PeClrCustomAttributeInfo["parent"]
    : { table: "null", tableId: -1, row: 0, raw: 0, valid: false };

export const createCustomAttributes = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders,
  modules: PeClrModuleInfo[],
  assembly: PeClrAssemblyInfo | null,
  assemblyRefs: PeClrAssemblyRefInfo[],
  typeRefs: PeClrTypeReferenceInfo[],
  typeDefs: PeClrTypeDefinitionInfo[],
  methodDefs: PeClrMethodDefinitionInfo[],
  memberRefs: PeClrMemberReferenceInfo[],
  moduleRefs: PeClrModuleReferenceInfo[]
): PeClrCustomAttributeInfo[] =>
  rows.map((row, index): PeClrCustomAttributeInfo => {
    const parent = cellIndex(row, "Parent");
    const constructor = cellIndex(row, "Type");
    const memberRef = constructor.tableId === TABLE_MEMBER_REF
      ? memberRefs[constructor.row - 1]
      : undefined;
    const methodDef = constructor.tableId === TABLE_METHOD_DEF
      ? methodDefs[constructor.row - 1]
      : undefined;
    const signature = memberRef?.signature ?? methodDef?.signature;
    const valueBlobIndex = cellNumber(row, "Value");
    const decoded = signature
      ? decodeCustomAttributeValue(
          heaps.getBlob(valueBlobIndex, `CustomAttribute row ${index + 1}.Value`),
          signature.parameterTypes,
          `CustomAttribute row ${index + 1}`
        )
      : {
          fixedArguments: [],
          namedArguments: [],
          issues: ["Constructor signature is unavailable; custom attribute value was not decoded."]
        };
    return {
      row: index + 1,
      parent,
      parentName: resolveMetadataIndexName(
        parent, modules, assembly, assemblyRefs, typeRefs, typeDefs, methodDefs, moduleRefs
      ),
      constructor,
      constructorName: memberRef?.name ?? methodDef?.name ?? null,
      attributeType: memberRef?.parentName ?? methodDef?.ownerType ?? null,
      valueBlobIndex,
      fixedArguments: decoded.fixedArguments,
      namedArguments: decoded.namedArguments,
      ...(decoded.issues?.length ? { issues: decoded.issues } : {})
    };
  });
