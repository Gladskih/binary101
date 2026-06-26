"use strict";

import type {
  PeClrAssemblyInfo,
  PeClrAssemblyRefInfo,
  PeClrMetadataIndex,
  PeClrMetadataTables,
  PeClrMethodDefinitionInfo,
  PeClrModuleInfo,
  PeClrModuleReferenceInfo,
  PeClrParameterInfo,
  PeClrTypeDefinitionInfo,
  PeClrTypeReferenceInfo
} from "./types.js";
import type { ClrHeapReaders } from "./metadata-heaps.js";
import { parseMethodSignature } from "./metadata-signatures.js";
import type { ClrMetadataRow, ClrParsedTableStream } from "./metadata-table-reader.js";
import { createCustomAttributes } from "./metadata-custom-attributes.js";
import {
  createExportedTypes,
  createFiles,
  createImplMaps,
  createManifestResources,
  createMemberRefs
} from "./metadata-derived-tables.js";
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
  TABLE_PARAM,
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
  const publicKey = heaps.getBlob(cellNumber(row, "PublicKey"), "Assembly row 1.PublicKey");
  return {
    row: 1,
    name: getString(heaps, row, "Name", "Assembly row 1"),
    culture: getString(heaps, row, "Culture", "Assembly row 1"),
    version: versionText(row),
    hashAlgorithm: cellNumber(row, "HashAlgId"),
    flags: cellNumber(row, "Flags"),
    ...(publicKey ? { publicKey: Array.from(publicKey) } : {})
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

const methodEndForType = (
  methodStart: number,
  nextMethodStart: number | null,
  methodRowCount: number
): number | null => {
  if (methodStart <= 0 || methodStart > methodRowCount) return null;
  if (nextMethodStart != null) return nextMethodStart > methodStart ? nextMethodStart - 1 : null;
  return methodRowCount;
};

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
    const nextMethodStart = nextRow ? cellIndex(nextRow, "MethodList").row : null;
    return {
      row: index + 1,
      name,
      namespace: namespaceName,
      fullName: fullName(namespaceName, name),
      flags: cellNumber(row, "Flags"),
      extends: cellIndex(row, "Extends"),
      fieldStart: cellIndex(row, "FieldList").row,
      methodStart,
      methodEnd: methodEndForType(methodStart, nextMethodStart, methodRowCount)
    };
  });

const ownerForMethod = (
  methodRow: number,
  typeDefs: PeClrTypeDefinitionInfo[]
): string | null =>
  typeDefs.find(typeDef =>
    typeDef.methodEnd != null && methodRow >= typeDef.methodStart && methodRow <= typeDef.methodEnd
  )?.fullName ?? null;

const createParameters = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders
): PeClrParameterInfo[] =>
  rows.map((row, index) => ({
    row: index + 1,
    flags: cellNumber(row, "Flags"),
    sequence: cellNumber(row, "Sequence"),
    name: getString(heaps, row, "Name", `Param row ${index + 1}`)
  }));

const parametersForMethod = (
  row: ClrMetadataRow,
  nextRow: ClrMetadataRow | undefined,
  parameters: PeClrParameterInfo[]
): PeClrParameterInfo[] => {
  const parameterStart = cellIndex(row, "ParamList").row;
  const nextParameterStart = nextRow ? cellIndex(nextRow, "ParamList").row : parameters.length + 1;
  if (parameterStart <= 0 || parameterStart > parameters.length || nextParameterStart <= parameterStart) {
    return [];
  }
  return parameters.slice(parameterStart - 1, Math.min(parameters.length, nextParameterStart - 1));
};

const createMethodDefs = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders,
  typeDefs: PeClrTypeDefinitionInfo[],
  parameters: PeClrParameterInfo[]
): PeClrMethodDefinitionInfo[] =>
  rows.map((row, index) => {
    const methodParameters = parametersForMethod(row, rows[index + 1], parameters);
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
      ...(signature ? { signature } : {}),
      ...(methodParameters.length ? { parameters: methodParameters } : {})
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
  const parameters = createParameters(tableRows(parsed, TABLE_PARAM), heaps);
  const methodDefs = createMethodDefs(tableRows(parsed, TABLE_METHOD_DEF), heaps, typeDefs, parameters);
  const resolutionTables = {
    modules, assembly, assemblyRefs, typeRefs, typeDefs, methodDefs, moduleRefs
  };
  const memberRefs = createMemberRefs(
    tableRows(parsed, TABLE_MEMBER_REF),
    heaps,
    resolutionTables
  );
  const implMaps = createImplMaps(
    tableRows(parsed, TABLE_IMPL_MAP),
    heaps,
    resolutionTables
  );
  const files = createFiles(tableRows(parsed, TABLE_FILE), heaps);
  const exportedTypes = createExportedTypes(tableRows(parsed, TABLE_EXPORTED_TYPE), heaps);
  const manifestResources = createManifestResources(tableRows(parsed, TABLE_MANIFEST_RESOURCE), heaps);
  const customAttributes = createCustomAttributes(
    tableRows(parsed, TABLE_CUSTOM_ATTRIBUTE),
    heaps,
    {
      modules, assembly, assemblyRefs, typeRefs,
      typeDefs, methodDefs, memberRefs, moduleRefs
    }
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
    parameters,
    memberRefs,
    moduleRefs,
    implMaps,
    files,
    exportedTypes,
    manifestResources,
    customAttributes
  };
};
