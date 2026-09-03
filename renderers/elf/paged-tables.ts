"use strict";

import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";
import { getNativeAotReflectionTypeTableModel } from "../native-aot/reflection.js";

export const getElfPagedTableModel = (
  elf: ElfParseResult,
  tableId: string
): PagedSortableTableModel | null =>
  getNativeAotReflectionTypeTableModel(elf.nativeAot?.reflection, tableId);
