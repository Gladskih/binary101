"use strict";

import {
  isPeWindowsParseResult,
  type PeParseResult,
  type PeWindowsParseResult
} from "../../analyzers/pe/index.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";
import { getDwarfPagedTableModel } from "../dwarf/paged-tables.js";
import {
  directIatEntrySize,
  directIatReferenceCounts
} from "./direct-iat-references.js";
import { getCoffDebugTableModel } from "../coff/debug.js";
import { getPeDisassemblyStringTableModel } from "./disassembly-strings.js";
import { createImportFunctionTableModel } from "./import-function-table.js";
import { getPeResourceTableModel } from "./resources.js";
import { getMsvcRttiPagedTableModel } from "./msvc-rtti-table.js";
import { getItaniumRttiTableModel } from "./itanium-rtti.js";
import { getLoadConfigReferenceTableModel } from "./load-config-reference-tables.js";
import {
  createGoRuntimeFunctionTableModel,
  GO_FUNCTION_TABLE_ID
} from "./go-runtime.js";
import { getNativeAotReflectionTypeTableModel } from "../native-aot/reflection.js";
import { getNativeAotInvokeTableModel } from "../native-aot/invoke-map.js";
import { getNativeAotStackTraceTableModel } from "../native-aot/stack-trace-map.js";
import { getNativeAotFunctionTableModel } from "../native-aot/function-maps.js";
import { createExportTableModel, EXPORT_TABLE_ID } from "./export-table.js";
import { analyzeTypeLibraryExports } from
  "../../analyzers/pe/resources/type-library-export-links.js";
import { getOmapTableModel } from "./omap.js";
import { createDRuntimeModuleTableModel, D_MODULE_TABLE_ID } from "./d-runtime.js";
import { createDRuntimeReferenceTableModel, D_REFERENCE_TABLE_ID } from "./d-runtime-references.js";
import { createClrMetadataTableModels } from "./clr-metadata.js";
import { getReadyToRunTableModel } from "./ready-to-run-tables.js";

const getClrTableModel = (pe: PeWindowsParseResult, tableId: string): PagedSortableTableModel | null =>
  tableId.startsWith("pe-clr-") && pe.clr?.meta?.tables
    ? createClrMetadataTableModels(pe.clr.meta.tables).find(model => model.id === tableId) ?? null : null;

const eagerImportMatch = (tableId: string): number | null => {
  const match = tableId.match(/^eager-import-(\d+)$/);
  return match?.[1] == null ? null : Number(match[1]);
};

const delayImportMatch = (tableId: string): number | null => {
  const match = tableId.match(/^delay-import-(\d+)$/);
  return match?.[1] == null ? null : Number(match[1]);
};

const getImportFunctionTableModel = (
  pe: PeWindowsParseResult,
  tableId: string
): PagedSortableTableModel | null => {
  const counts = directIatReferenceCounts(pe);
  const entrySize = directIatEntrySize(pe);
  const eagerIndex = eagerImportMatch(tableId);
  if (eagerIndex != null) {
    const entry = pe.imports.entries[eagerIndex];
    return entry?.functions?.length
      ? createImportFunctionTableModel(
        entry.functions,
        tableId,
        entry.firstThunkRva,
        counts,
        entrySize
      )
      : null;
  }
  const delayIndex = delayImportMatch(tableId);
  if (delayIndex == null) return null;
  const entry = pe.delayImports?.entries[delayIndex];
  return entry?.functions?.length
    ? createImportFunctionTableModel(
      entry.functions,
      tableId,
      entry.ImportAddressTableRVA,
      counts,
      entrySize
    )
    : null;
};

const getPeDebugCoffTableModel = (
  pe: PeParseResult,
  tableId: string
): PagedSortableTableModel | null => {
  const topLevel = pe.coffDebug
    ? getCoffDebugTableModel(pe.coffDebug, tableId, "pe-coff-symbols")
    : null;
  if (topLevel) return topLevel;
  if (!isPeWindowsParseResult(pe)) return null;
  const dwarf = getDwarfPagedTableModel(pe.dwarf, tableId);
  if (dwarf) return dwarf;
  const match = tableId.match(/^pe-debug-entry-(\d+)-coff-/);
  if (!match?.[1]) return null;
  const entry = pe.debug?.entries?.[Number(match[1])];
  return entry?.coff ? getCoffDebugTableModel(entry.coff, tableId, match[0].slice(0, -1)) : null;
};

const getNativeAotTableModel = (
  pe: PeWindowsParseResult, tableId: string
): PagedSortableTableModel | null => {
  if (pe.nativeAotCandidate?.status !== "confirmed") return null;
  const metadata = pe.nativeAotCandidate;
  return getNativeAotReflectionTypeTableModel(metadata.reflection, tableId) ??
    getNativeAotInvokeTableModel(metadata.invokeMap, tableId) ??
    getNativeAotStackTraceTableModel(metadata.stackTraceMap, tableId) ??
    getNativeAotFunctionTableModel(metadata.functionMaps, tableId);
};

type TableResolver = (pe: PeWindowsParseResult, tableId: string) => PagedSortableTableModel | null;

const windowsTableResolvers: TableResolver[] = [
  getPeDisassemblyStringTableModel, getOmapTableModel, getClrTableModel,
  (pe, id) => getReadyToRunTableModel(pe.clr, id),
  (pe, id) => id === EXPORT_TABLE_ID && pe.exports
    ? createExportTableModel(pe.exports.entries,
      analyzeTypeLibraryExports(pe.resources, pe.exports).matches) : null,
  (pe, id) => id === GO_FUNCTION_TABLE_ID && pe.goRuntime
    ? createGoRuntimeFunctionTableModel(pe.goRuntime.functions) : null,
  (pe, id) => id === D_MODULE_TABLE_ID && pe.dRuntime
    ? createDRuntimeModuleTableModel(pe.dRuntime.modules) : null,
  (pe, id) => id === D_REFERENCE_TABLE_ID && pe.dRuntime
    ? createDRuntimeReferenceTableModel(pe.dRuntime.modules) : null,
  (pe, id) => pe.loadcfg?.references
    ? getLoadConfigReferenceTableModel(pe.loadcfg.references, id) : null,
  getMsvcRttiPagedTableModel,
  (pe, id) => getItaniumRttiTableModel(pe.itaniumRtti, id),
  getImportFunctionTableModel, getNativeAotTableModel,
  (pe, id) => getPeResourceTableModel(pe.resources, id)
];

export const getPePagedTableModel = (
  pe: PeParseResult, tableId: string
): PagedSortableTableModel | null => {
  const debug = getPeDebugCoffTableModel(pe, tableId);
  if (debug) return debug;
  if (!isPeWindowsParseResult(pe)) return null;
  for (const resolve of windowsTableResolvers) {
    const table = resolve(pe, tableId);
    if (table) return table;
  }
  return null;
};
