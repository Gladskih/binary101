"use strict";

import type {
  PeClrAssemblyInfo,
  PeClrAssemblyRefInfo,
  PeClrExportedTypeInfo,
  PeClrFileInfo,
  PeClrImplementationMapInfo,
  PeClrManifestResourceInfo,
  PeClrMethodDefinitionInfo,
  PeClrModuleInfo,
  PeClrModuleReferenceInfo,
  PeClrTypeDefinitionInfo,
  PeClrTypeReferenceInfo
} from "./types.js";
import type { ClrHeapReaders } from "./metadata-heaps.js";
import type { ClrMetadataRow } from "./metadata-table-reader.js";
import { parseMemberRefSignature } from "./metadata-signatures.js";
import { resolveMetadataIndexName } from "./metadata-name-resolver.js";

export type ClrMetadataResolutionTables = {
  modules: PeClrModuleInfo[];
  assembly: PeClrAssemblyInfo | null;
  assemblyRefs: PeClrAssemblyRefInfo[];
  typeRefs: PeClrTypeReferenceInfo[];
  typeDefs: PeClrTypeDefinitionInfo[];
  methodDefs: PeClrMethodDefinitionInfo[];
  moduleRefs: PeClrModuleReferenceInfo[];
};

const cellNumber = (row: ClrMetadataRow, name: string): number =>
  typeof row[name] === "number" ? row[name] : 0;

const cellIndex = (row: ClrMetadataRow, name: string) =>
  typeof row[name] === "object"
    ? row[name]
    : { table: "null", tableId: -1, row: 0, raw: 0, valid: false };

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

const fullName = (namespaceName: string | null, name: string | null): string | null => {
  if (!name) return null;
  return namespaceName ? `${namespaceName}.${name}` : name;
};

export const createMemberRefs = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders,
  tables: ClrMetadataResolutionTables
) =>
  rows.map((row, index) => {
    const signatureBlobIndex = cellNumber(row, "Signature");
    const parent = cellIndex(row, "Class");
    const parentName = resolveMetadataIndexName(
      parent,
      tables.modules,
      tables.assembly,
      tables.assemblyRefs,
      tables.typeRefs,
      tables.typeDefs,
      tables.methodDefs,
      tables.moduleRefs
    );
    const context = `MemberRef row ${index + 1}.Signature`;
    const signature = parseMemberRefSignature(heaps.getBlob(signatureBlobIndex, context), context);
    return {
      row: index + 1,
      name: getString(heaps, row, "Name", `MemberRef row ${index + 1}`),
      parent,
      parentName,
      signatureBlobIndex,
      ...(signature ? { signature } : {})
    };
  });

export const createImplMaps = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders,
  tables: ClrMetadataResolutionTables
): PeClrImplementationMapInfo[] =>
  rows.map((row, index): PeClrImplementationMapInfo => {
    const member = cellIndex(row, "MemberForwarded");
    return {
      row: index + 1,
      mappingFlags: cellNumber(row, "MappingFlags"),
      member,
      memberName: resolveMetadataIndexName(
        member,
        tables.modules,
        tables.assembly,
        tables.assemblyRefs,
        tables.typeRefs,
        tables.typeDefs,
        tables.methodDefs,
        tables.moduleRefs
      ),
      importName: getString(heaps, row, "ImportName", `ImplMap row ${index + 1}`),
      importScopeName: tables.moduleRefs[cellIndex(row, "ImportScope").row - 1]?.name ?? null
    };
  });

export const createFiles = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders
): PeClrFileInfo[] =>
  rows.map((row, index): PeClrFileInfo => ({
    row: index + 1,
    name: getString(heaps, row, "Name", `File row ${index + 1}`),
    flags: cellNumber(row, "Flags"),
    hashValueSize: blobSize(heaps, row, "HashValue", `File row ${index + 1}`)
  }));

export const createExportedTypes = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders
): PeClrExportedTypeInfo[] =>
  rows.map((row, index): PeClrExportedTypeInfo => {
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

export const createManifestResources = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders
): PeClrManifestResourceInfo[] =>
  rows.map((row, index): PeClrManifestResourceInfo => ({
    row: index + 1,
    name: getString(heaps, row, "Name", `ManifestResource row ${index + 1}`),
    offset: cellNumber(row, "Offset"),
    flags: cellNumber(row, "Flags"),
    implementation: cellIndex(row, "Implementation")
  }));
