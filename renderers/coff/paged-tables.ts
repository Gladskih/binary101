"use strict";

import type { CoffObjectParseResult } from "../../analyzers/coff/types.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";
import { getCoffDebugTableModel } from "./debug.js";
import { getCoffRelocationTableModel } from "./relocations.js";
import {
  COFF_SECTION_TABLE_ID,
  createCoffSectionTableModel
} from "./sections.js";

export const getCoffPagedTableModel = (
  coff: CoffObjectParseResult,
  tableId: string
): PagedSortableTableModel | null => {
  if (tableId === COFF_SECTION_TABLE_ID) return createCoffSectionTableModel(coff, tableId);
  const relocationTableModel = getCoffRelocationTableModel(coff, tableId);
  if (relocationTableModel) return relocationTableModel;
  return coff.coffDebug
    ? getCoffDebugTableModel(coff.coffDebug, tableId, "coff-symbols")
    : null;
};
