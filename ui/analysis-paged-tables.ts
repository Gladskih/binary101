"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import type { CoffObjectParseResult } from "../analyzers/coff/types.js";
import type { PeParseResult } from "../analyzers/pe/index.js";
import { getCoffPagedTableModel } from "../renderers/coff/paged-tables.js";
import { getPePagedTableModel } from "../renderers/pe/paged-tables.js";
import {
  enhancePagedSortableTables,
  type PagedSortableTableSnapshot
} from "./paged-sortable-tables.js";
export { enhanceAnalysisEntrypointExplorer } from "./pe-entrypoint-explorer.js";

export const enhancePeDisassemblyPagedTables = (
  root: ParentNode,
  pe: PeParseResult,
  snapshots: readonly PagedSortableTableSnapshot[] = []
): void => {
  enhancePagedSortableTables(
    root,
    tableId => getPePagedTableModel(pe, tableId),
    snapshots
  );
};

const enhanceCoffPagedTables = (
  root: ParentNode,
  coff: CoffObjectParseResult,
  snapshots: readonly PagedSortableTableSnapshot[] = []
): void => {
  enhancePagedSortableTables(
    root,
    tableId => getCoffPagedTableModel(coff, tableId),
    snapshots
  );
};

export const enhanceAnalysisPagedTables = (
  root: ParentNode,
  result: ParseForUiResult,
  snapshots: readonly PagedSortableTableSnapshot[] = []
): void => {
  if (result.analyzer === "pe") {
    enhancePeDisassemblyPagedTables(root, result.parsed, snapshots);
  } else if (result.analyzer === "coff") {
    enhanceCoffPagedTables(root, result.parsed, snapshots);
  }
};
