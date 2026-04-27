"use strict";

import type {
  PeClrAssemblyInfo,
  PeClrAssemblyRefInfo,
  PeClrMetadataIndex,
  PeClrMethodDefinitionInfo,
  PeClrModuleInfo,
  PeClrModuleReferenceInfo,
  PeClrTypeDefinitionInfo,
  PeClrTypeReferenceInfo
} from "./types.js";
import {
  TABLE_ASSEMBLY,
  TABLE_ASSEMBLY_REF,
  TABLE_METHOD_DEF,
  TABLE_MODULE,
  TABLE_MODULE_REF,
  TABLE_TYPE_DEF,
  TABLE_TYPE_REF
} from "./metadata-schema.js";

export const resolveMetadataIndexName = (
  index: PeClrMetadataIndex,
  modules: PeClrModuleInfo[],
  assembly: PeClrAssemblyInfo | null,
  assemblyRefs: PeClrAssemblyRefInfo[],
  typeRefs: PeClrTypeReferenceInfo[],
  typeDefs: PeClrTypeDefinitionInfo[],
  methodDefs: PeClrMethodDefinitionInfo[],
  moduleRefs: PeClrModuleReferenceInfo[]
): string | null => {
  if (index.row === 0) return null;
  if (index.tableId === TABLE_MODULE) return modules[index.row - 1]?.name ?? null;
  if (index.tableId === TABLE_ASSEMBLY) return assembly?.name ?? null;
  if (index.tableId === TABLE_ASSEMBLY_REF) return assemblyRefs[index.row - 1]?.name ?? null;
  if (index.tableId === TABLE_TYPE_REF) return typeRefs[index.row - 1]?.fullName ?? null;
  if (index.tableId === TABLE_TYPE_DEF) return typeDefs[index.row - 1]?.fullName ?? null;
  if (index.tableId === TABLE_METHOD_DEF) return methodDefs[index.row - 1]?.name ?? null;
  if (index.tableId === TABLE_MODULE_REF) return moduleRefs[index.row - 1]?.name ?? null;
  return null;
};
