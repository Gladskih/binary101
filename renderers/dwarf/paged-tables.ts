import type { DwarfAnalysis } from "../../analyzers/dwarf/types.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";
import { createDwarfEntityTableModel } from "./entities.js";
import { createDwarfSourceLineTableModel } from "./source-lines.js";
import { createDwarfMacroTableModel } from "./macros.js";
import { getDwarfLookupTableModel } from "./lookups.js";

export const getDwarfPagedTableModel = (
  dwarf: DwarfAnalysis | undefined, tableId: string
): PagedSortableTableModel | null => {
  if (!dwarf || !tableId.startsWith("dwarf-")) return null;
  if (tableId === "dwarf-entities") return createDwarfEntityTableModel(dwarf);
  const macro = dwarf.macros?.find(macro => tableId === `dwarf-macros-${macro.sectionName}-${macro.offset}`);
  if (macro) return createDwarfMacroTableModel(dwarf, macro);
  const lookup = getDwarfLookupTableModel(dwarf, tableId);
  if (lookup) return lookup;
  const program = dwarf.linePrograms.find(program => tableId === "dwarf-lines-" + program.offset);
  return program ? createDwarfSourceLineTableModel(dwarf, program) : null;
};
