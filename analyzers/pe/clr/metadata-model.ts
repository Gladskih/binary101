"use strict";

import type {
  PeClrAssemblyInfo,
  PeClrAssemblyRefInfo,
  PeClrExportedTypeInfo,
  PeClrFileInfo,
  PeClrImplementationMapInfo,
  PeClrManifestResourceInfo,
  PeClrMetadataIndex,
  PeClrMetadataTables,
  PeClrMethodDefinitionInfo,
  PeClrModuleInfo,
  PeClrModuleReferenceInfo,
  PeClrTypeDefinitionInfo,
  PeClrTypeReferenceInfo
} from "./types.js";
import type { ClrHeapReaders } from "./metadata-heaps.js";
import { parseMethodSignature } from "./metadata-signatures.js";
import type { ClrMetadataRow, ClrParsedTableStream } from "./metadata-table-reader.js";
import { createCustomAttributes } from "./metadata-custom-attributes.js";
import { resolveMetadataIndexName } from "./metadata-name-resolver.js";
import {
  TABLE_ASSEMBLY,
  TABLE_ASSEMBLY_REF,
  TABLE_CUSTOM_ATTRIBUTE,
  TABLE_EXPORTED_TYPE,
  TABLE_FILE,
  TABLE_IMPL_MAP,
  TABLE_MANIFEST_RESOURCE,
  TABLE_MEMBER_REF,
  TABLE_METHOD_DEF,
  TABLE_MODULE,
  TABLE_MODULE_REF,
  TABLE_TYPE_DEF,
  TABLE_TYPE_REF
} from "./metadata-schema.js";

const cellNumber = (row: ClrMetadataRow, name: string): number =>
  typeof row[name] === "number" ? row[name] : 0;

const cellIndex = (row: ClrMetadataRow, name: string): PeClrMetadataIndex =>
  typeof row[name] === "object"
    ? row[name] as PeClrMetadataIndex
    : { table: "null", tableId: -1, row: 0, raw: 0, valid: false };

const tableRows = (parsed: ClrParsedTableStream, tableId: number): ClrMetadataRow[] =>
  parsed.tables.get(tableId)?.rows ?? [];

const maskHex = (value: bigint): string => `0x${value.toString(16).padStart(16, "0")}`;

const versionText = (row: ClrMetadataRow): string =>
  `${cellNumber(row, "MajorVersion")}.${cellNumber(row, "MinorVersion")}.` +
  `${cellNumber(row, "BuildNumber")}.${cellNumber(row, "RevisionNumber")}`;

const fullName = (namespaceName: string | null, name: string | null): string | null => {
  if (!name) return null;
  return namespaceName ? `${namespaceName}.${name}` : name;
};

const getString = (
  heaps: ClrHeapReaders,
  row: ClrMetadataRow,
  fieldName: string,
  context: string
): string | null => heaps.getString(cellNumber(row, fieldName), `${context}.${fieldName}`);

const blobSize = (
  heaps: ClrHeapReaders,
  row: ClrMetadataRow,
  fieldName: string,
  context: string
): number | null => heaps.getBlobSize(cellNumber(row, fieldName), `${context}.${fieldName}`);

const createModules = (rows: ClrMetadataRow[], heaps: ClrHeapReaders): PeClrModuleInfo[] =>
  rows.map((row, index) => ({
    row: index + 1,
    name: getString(heaps, row, "Name", `Module row ${index + 1}`),
    mvid: heaps.getGuid(cellNumber(row, "Mvid"), `Module row ${index + 1}.Mvid`)
  }));

const createAssembly = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders
): PeClrAssemblyInfo | null => {
  const row = rows[0];
  if (!row) return null;
  return {
    row: 1,
    name: getString(heaps, row, "Name", "Assembly row 1"),
    culture: getString(heaps, row, "Culture", "Assembly row 1"),
    version: versionText(row),
    hashAlgorithm: cellNumber(row, "HashAlgId"),
    flags: cellNumber(row, "Flags"),
    publicKeySize: blobSize(heaps, row, "PublicKey", "Assembly row 1")
  };
};

const createAssemblyRefs = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders
): PeClrAssemblyRefInfo[] =>
  rows.map((row, index) => ({
    row: index + 1,
    name: getString(heaps, row, "Name", `AssemblyRef row ${index + 1}`),
    culture: getString(heaps, row, "Culture", `AssemblyRef row ${index + 1}`),
    version: versionText(row),
    flags: cellNumber(row, "Flags"),
    publicKeyOrTokenSize: blobSize(heaps, row, "PublicKeyOrToken", `AssemblyRef row ${index + 1}`),
    hashValueSize: blobSize(heaps, row, "HashValue", `AssemblyRef row ${index + 1}`)
  }));

const createTypeRefs = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders
): PeClrTypeReferenceInfo[] =>
  rows.map((row, index) => {
    const name = getString(heaps, row, "TypeName", `TypeRef row ${index + 1}`);
    const namespaceName = getString(heaps, row, "TypeNamespace", `TypeRef row ${index + 1}`);
    return {
      row: index + 1,
      name,
      namespace: namespaceName,
      resolutionScope: cellIndex(row, "ResolutionScope"),
      fullName: fullName(namespaceName, name)
    };
  });

const createTypeDefs = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders,
  methodRowCount: number
): PeClrTypeDefinitionInfo[] =>
  rows.map((row, index) => {
    const nextRow = rows[index + 1];
    const name = getString(heaps, row, "TypeName", `TypeDef row ${index + 1}`);
    const namespaceName = getString(heaps, row, "TypeNamespace", `TypeDef row ${index + 1}`);
    const methodStart = cellIndex(row, "MethodList").row;
    const nextMethodStart = nextRow ? cellIndex(nextRow, "MethodList").row : methodRowCount + 1;
    return {
      row: index + 1,
      name,
      namespace: namespaceName,
      fullName: fullName(namespaceName, name),
      flags: cellNumber(row, "Flags"),
      extends: cellIndex(row, "Extends"),
      fieldStart: cellIndex(row, "FieldList").row,
      methodStart,
      methodEnd: methodStart > 0 && nextMethodStart > methodStart ? nextMethodStart - 1 : null
    };
  });

const ownerForMethod = (
  methodRow: number,
  typeDefs: PeClrTypeDefinitionInfo[]
): string | null =>
  typeDefs.find(typeDef =>
    methodRow >= typeDef.methodStart && (typeDef.methodEnd == null || methodRow <= typeDef.methodEnd)
  )?.fullName ?? null;

const createMethodDefs = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders,
  typeDefs: PeClrTypeDefinitionInfo[]
): PeClrMethodDefinitionInfo[] =>
  rows.map((row, index) => {
    const signatureBlobIndex = cellNumber(row, "Signature");
    const context = `MethodDef row ${index + 1}.Signature`;
    const signature = parseMethodSignature(heaps.getBlob(signatureBlobIndex, context), context);
    return {
      row: index + 1,
      name: getString(heaps, row, "Name", `MethodDef row ${index + 1}`),
      ownerType: ownerForMethod(index + 1, typeDefs),
      rva: cellNumber(row, "RVA"),
      implFlags: cellNumber(row, "ImplFlags"),
      flags: cellNumber(row, "Flags"),
      signatureBlobIndex,
      ...(signature ? { signature } : {})
    };
  });

const createModuleRefs = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders
): PeClrModuleReferenceInfo[] =>
  rows.map((row, index) => ({
    row: index + 1,
    name: getString(heaps, row, "Name", `ModuleRef row ${index + 1}`)
  }));

export const buildClrMetadataTables = (
  parsed: ClrParsedTableStream,
  heaps: ClrHeapReaders
): PeClrMetadataTables => {
  const modules = createModules(tableRows(parsed, TABLE_MODULE), heaps);
  const moduleRefs = createModuleRefs(tableRows(parsed, TABLE_MODULE_REF), heaps);
  const assembly = createAssembly(tableRows(parsed, TABLE_ASSEMBLY), heaps);
  const assemblyRefs = createAssemblyRefs(tableRows(parsed, TABLE_ASSEMBLY_REF), heaps);
  const typeRefs = createTypeRefs(tableRows(parsed, TABLE_TYPE_REF), heaps);
  const typeDefs = createTypeDefs(
    tableRows(parsed, TABLE_TYPE_DEF),
    heaps,
    tableRows(parsed, TABLE_METHOD_DEF).length
  );
  const methodDefs = createMethodDefs(tableRows(parsed, TABLE_METHOD_DEF), heaps, typeDefs);
  const memberRefs = tableRows(parsed, TABLE_MEMBER_REF).map((row, index) => {
    const signatureBlobIndex = cellNumber(row, "Signature");
    const parent = cellIndex(row, "Class");
    const parentName = resolveMetadataIndexName(
      parent, modules, assembly, assemblyRefs, typeRefs, typeDefs, methodDefs, moduleRefs
    );
    const context = `MemberRef row ${index + 1}.Signature`;
    const signature = parseMethodSignature(heaps.getBlob(signatureBlobIndex, context), context);
    return {
      row: index + 1,
      name: getString(heaps, row, "Name", `MemberRef row ${index + 1}`),
      parent,
      parentName,
      signatureBlobIndex,
      ...(signature ? { signature } : {})
    };
  });
  const implMaps = tableRows(parsed, TABLE_IMPL_MAP).map((row, index): PeClrImplementationMapInfo => {
    const member = cellIndex(row, "MemberForwarded");
    return {
      row: index + 1,
      mappingFlags: cellNumber(row, "MappingFlags"),
      member,
      memberName: resolveMetadataIndexName(
        member, modules, assembly, assemblyRefs, typeRefs, typeDefs, methodDefs, moduleRefs
      ),
      importName: getString(heaps, row, "ImportName", `ImplMap row ${index + 1}`),
      importScopeName: moduleRefs[cellIndex(row, "ImportScope").row - 1]?.name ?? null
    };
  });
  const files = tableRows(parsed, TABLE_FILE).map((row, index): PeClrFileInfo => ({
    row: index + 1,
    name: getString(heaps, row, "Name", `File row ${index + 1}`),
    flags: cellNumber(row, "Flags"),
    hashValueSize: blobSize(heaps, row, "HashValue", `File row ${index + 1}`)
  }));
  const exportedTypes = tableRows(parsed, TABLE_EXPORTED_TYPE).map((row, index): PeClrExportedTypeInfo => {
    const name = getString(heaps, row, "TypeName", `ExportedType row ${index + 1}`);
    const namespaceName = getString(heaps, row, "TypeNamespace", `ExportedType row ${index + 1}`);
    return {
      row: index + 1,
      name,
      namespace: namespaceName,
      fullName: fullName(namespaceName, name),
      flags: cellNumber(row, "Flags"),
      typeDefId: cellNumber(row, "TypeDefId"),
      implementation: cellIndex(row, "Implementation")
    };
  });
  const manifestResources = tableRows(parsed, TABLE_MANIFEST_RESOURCE)
    .map((row, index): PeClrManifestResourceInfo => ({
      row: index + 1,
      name: getString(heaps, row, "Name", `ManifestResource row ${index + 1}`),
      offset: cellNumber(row, "Offset"),
      flags: cellNumber(row, "Flags"),
      implementation: cellIndex(row, "Implementation")
    }));
  const customAttributes = createCustomAttributes(
    tableRows(parsed, TABLE_CUSTOM_ATTRIBUTE),
    heaps,
    modules,
    assembly,
    assemblyRefs,
    typeRefs,
    typeDefs,
    methodDefs,
    memberRefs,
    moduleRefs
  );
  return {
    streamName: parsed.streamName,
    majorVersion: parsed.majorVersion,
    minorVersion: parsed.minorVersion,
    heapSizes: parsed.heapSizes,
    largestRidLog2: parsed.largestRidLog2,
    ...(typeof parsed.extraData === "number" ? { extraData: parsed.extraData } : {}),
    validMask: maskHex(parsed.validMask),
    sortedMask: maskHex(parsed.sortedMask),
    heapIndexSizes: parsed.heapIndexSizes,
    rowCounts: parsed.rowCounts,
    modules,
    assembly,
    assemblyRefs,
    typeRefs,
    typeDefs,
    methodDefs,
    memberRefs,
    moduleRefs,
    implMaps,
    files,
    exportedTypes,
    manifestResources,
    customAttributes
  };
};
