"use strict";

import type {
  PeClrAssemblyInfo,
  PeClrAssemblyRefInfo,
  PeClrCustomAttributeInfo,
  PeClrFieldInfo,
  PeClrMemberReferenceInfo,
  PeClrMethodDefinitionInfo,
  PeClrModuleInfo,
  PeClrModuleReferenceInfo,
  PeClrTypeDefinitionInfo,
  PeClrTypeReferenceInfo,
  PeClrMethodSignature
} from "./types.js";
import type { ClrHeapReaders } from "./metadata-heaps.js";
import type { ClrMetadataRow } from "./metadata-table-reader.js";
import { decodeCustomAttributeValue } from "./metadata-attributes.js";
import { TABLE_MEMBER_REF, TABLE_METHOD_DEF } from "./metadata-schema.js";
import { resolveMetadataIndexName } from "./metadata-name-resolver.js";
import { createEnumUnderlyingTypes } from "./metadata-enums.js";

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
  return resolveParameterMatch(match, typeRefs, typeDefs);
};

const resolveParameterMatch = (
  match: RegExpMatchArray,
  typeRefs: PeClrTypeReferenceInfo[],
  typeDefs: PeClrTypeDefinitionInfo[]
): string | null => {
  const tableName = match[2];
  const row = Number(match[3]);
  // A TypeRef can point into another assembly with the same type name as a local enum.
  // Keep its identity separate; the owning assembly is needed to determine the underlying type.
  if (match[1] === "valuetype" && tableName === "TypeRef") {
    return enumReferenceName(row, typeRefs, match[4] ?? "");
  }
  const resolved = tableName === "TypeRef"
    ? typeRefs[row - 1]?.fullName : typeDefs[row - 1]?.fullName;
  return resolved ? `${resolved}${match[4] ?? ""}` : match[0];
};

const enumReferenceName = (row: number, references: PeClrTypeReferenceInfo[], suffix: string): string =>
  `enum TypeRef#${row} (${references[row - 1]?.fullName ?? "unresolved"})${suffix}`;

const resolveSignatureParameterTypes = (
  parameterTypes: Array<string | null>,
  typeRefs: PeClrTypeReferenceInfo[],
  typeDefs: PeClrTypeDefinitionInfo[]
): Array<string | null> =>
  parameterTypes.map(parameterType => resolveSignatureParameterType(parameterType, typeRefs, typeDefs));

export type ClrMetadataReferenceGraph = {
  modules: PeClrModuleInfo[];
  assembly: PeClrAssemblyInfo | null;
  assemblyRefs: PeClrAssemblyRefInfo[];
  typeRefs: PeClrTypeReferenceInfo[];
  typeDefs: PeClrTypeDefinitionInfo[];
  methodDefs: PeClrMethodDefinitionInfo[];
  memberRefs: PeClrMemberReferenceInfo[];
  moduleRefs: PeClrModuleReferenceInfo[];
  fields?: PeClrFieldInfo[];
};

export const createCustomAttributes = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders,
  references: ClrMetadataReferenceGraph
): PeClrCustomAttributeInfo[] => {
  const enumTypes = createEnumUnderlyingTypes(references.typeDefs, references.typeRefs, references.fields ?? []);
  return rows.map((row, index): PeClrCustomAttributeInfo => {
    const parent = cellIndex(row, "Parent");
    const constructor = cellIndex(row, "Type");
    const target = resolveConstructor(constructor, references);
    const valueBlobIndex = cellNumber(row, "Value");
    const decoded = decodeAttribute(row, heaps, references, target?.signature, enumTypes, index + 1);
    return {
      row: index + 1,
      parent,
      parentName: resolveMetadataIndexName(
        parent,
        references.modules,
        references.assembly,
        references.assemblyRefs,
        references.typeRefs,
        references.typeDefs,
        references.methodDefs,
        references.moduleRefs
      ),
      constructor,
      constructorName: target?.name ?? null,
      attributeType: constructorTypeName(target),
      valueBlobIndex,
      fixedArguments: decoded.fixedArguments,
      namedArguments: decoded.namedArguments,
      ...(decoded.issues?.length ? { issues: decoded.issues } : {})
    };
  });
};

const resolveConstructor = (
  constructor: PeClrCustomAttributeInfo["parent"],
  references: ClrMetadataReferenceGraph
): PeClrMemberReferenceInfo | PeClrMethodDefinitionInfo | undefined => {
  if (!constructor.valid || !constructor.row) return undefined;
  if (constructor.tableId === TABLE_MEMBER_REF) return references.memberRefs[constructor.row - 1];
  if (constructor.tableId === TABLE_METHOD_DEF) return references.methodDefs[constructor.row - 1];
  return undefined;
};

const constructorTypeName = (
  target: PeClrMemberReferenceInfo | PeClrMethodDefinitionInfo | undefined
): string | null => {
  if (!target) return null;
  return "parentName" in target ? target.parentName : target.ownerType;
};

const decodeAttribute = (
  row: ClrMetadataRow,
  heaps: ClrHeapReaders,
  references: ClrMetadataReferenceGraph,
  signature: PeClrMethodSignature | undefined,
  enumTypes: ReadonlyMap<string, string>,
  rowNumber: number
) => {
  if (!signature || !validConstructorSignature(signature)) {
    return { fixedArguments: [], namedArguments: [],
      issues: ["Constructor signature is unavailable or malformed; custom attribute value was not decoded."] };
  }
  return decodeCustomAttributeValue(
    heaps.getBlob(cellNumber(row, "Value"), `CustomAttribute row ${rowNumber}.Value`),
    resolveSignatureParameterTypes(signature.parameterTypes, references.typeRefs, references.typeDefs),
    `CustomAttribute row ${rowNumber}`, enumTypes
  );
};

const validConstructorSignature = (signature: PeClrMethodSignature): boolean =>
  // CustomAttributeDecoder.DecodeValue requires a non-generic method returning VOID.
  // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Reflection.Metadata/src/System/Reflection/Metadata/Ecma335/CustomAttributeDecoder.cs
  !signature.issues?.length && signature.returnType === "void" &&
  (signature.callingConvention & 0x10) === 0 &&
  [0, 1, 2, 3, 4, 5, 9, 0x0b].includes(signature.callingConvention & 0x0f);
