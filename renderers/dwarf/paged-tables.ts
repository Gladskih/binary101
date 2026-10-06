import type { DwarfAnalysis } from "../../analyzers/dwarf/types.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";
import { createDwarfEntityTableModel } from "./entities.js";
import { createDwarfSourceLineTableModel } from "./source-lines.js";

export const getDwarfPagedTableModel = (
  dwarf: DwarfAnalysis | undefined, tableId: string
): PagedSortableTableModel | null => {
  if (!dwarf || !tableId.startsWith("dwarf-")) return null;
  if (tableId === "dwarf-entities") return createDwarfEntityTableModel(dwarf);
  const program = dwarf.linePrograms.find(program => tableId === "dwarf-lines-" + program.offset);
  return program ? createDwarfSourceLineTableModel(dwarf, program) : null;
};
