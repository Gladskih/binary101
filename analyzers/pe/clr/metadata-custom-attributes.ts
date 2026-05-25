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

const resolveSignatureParameterType = (
  parameterType: string | null,
  typeRefs: PeClrTypeReferenceInfo[],
  typeDefs: PeClrTypeDefinitionInfo[]
): string | null => {
  const match = parameterType?.match(/^(class|valuetype) (TypeDef|TypeRef)#(\d+)(\[\])?$/);
  if (!match) return parameterType;
  const tableName = match[2];
  const row = Number(match[3]);
  const resolved = tableName === "TypeRef"
    ? typeRefs[row - 1]?.fullName
    : typeDefs[row - 1]?.fullName;
  return resolved ? `${resolved}${match[4] ?? ""}` : parameterType;
};

const resolveSignatureParameterTypes = (
  parameterTypes: Array<string | null>,
  typeRefs: PeClrTypeReferenceInfo[],
  typeDefs: PeClrTypeDefinitionInfo[]
): Array<string | null> =>
  parameterTypes.map(parameterType => resolveSignatureParameterType(parameterType, typeRefs, typeDefs));

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
          resolveSignatureParameterTypes(signature.parameterTypes, typeRefs, typeDefs),
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
