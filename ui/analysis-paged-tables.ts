"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { isPeWindowsParseResult, type PeWindowsParseResult } from "../analyzers/pe/index.js";
import { getPeDisassemblyStringTableModel } from "../renderers/pe/disassembly-strings.js";
import {
  enhancePagedSortableTables,
  type PagedSortableTableSnapshot
} from "./paged-sortable-tables.js";

export const enhancePeDisassemblyPagedTables = (
  root: ParentNode,
  pe: PeWindowsParseResult,
  snapshots: readonly PagedSortableTableSnapshot[] = []
): void => {
  enhancePagedSortableTables(
    root,
    tableId => getPeDisassemblyStringTableModel(pe, tableId),
    snapshots
  );
};

export const enhanceAnalysisPagedTables = (
  root: ParentNode,
  result: ParseForUiResult,
  snapshots: readonly PagedSortableTableSnapshot[] = []
): void => {
  if (result.analyzer !== "pe" || !result.parsed || !isPeWindowsParseResult(result.parsed)) {
    return;
  }
  enhancePeDisassemblyPagedTables(root, result.parsed, snapshots);
};
