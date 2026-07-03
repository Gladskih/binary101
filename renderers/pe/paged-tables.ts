"use strict";

import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";
import {
  directIatEntrySize,
  directIatReferenceCounts
} from "./direct-iat-references.js";
import { getCoffDebugTableModel } from "./debug-coff.js";
import { getPeDisassemblyStringTableModel } from "./disassembly-strings.js";
import { createImportFunctionTableModel } from "./import-function-table.js";
import { getPeResourceTableModel } from "./resources.js";

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

const getPeCoffDebugTableModel = (
  pe: PeWindowsParseResult,
  tableId: string
): PagedSortableTableModel | null => {
  const topLevel = pe.coffDebug
    ? getCoffDebugTableModel(pe.coffDebug, tableId, "pe-coff-symbols")
    : null;
  if (topLevel) return topLevel;
  const match = tableId.match(/^pe-debug-entry-(\d+)-coff-/);
  if (!match?.[1]) return null;
  const entry = pe.debug?.entries?.[Number(match[1])];
  return entry?.coff ? getCoffDebugTableModel(entry.coff, tableId, match[0].slice(0, -1)) : null;
};

export const getPePagedTableModel = (
  pe: PeWindowsParseResult,
  tableId: string
): PagedSortableTableModel | null =>
  getPeDisassemblyStringTableModel(pe, tableId) ??
  getPeCoffDebugTableModel(pe, tableId) ??
  getImportFunctionTableModel(pe, tableId) ??
  getPeResourceTableModel(pe.resources, tableId);
