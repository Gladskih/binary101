import type {
  ElfInstructionSetProgress, ElfInstructionSetUsage
} from "../analyzers/elf/disassembly-types.js";
import { renderAarch64RequirementTable } from "../renderers/aarch64-instruction-sets.js";
import {
  captureSortableTableState, enhanceSortableTables, restoreSortableTableState
} from "./sortable-tables.js";

const updateCounts = (container: HTMLElement, sets: ElfInstructionSetUsage[]): boolean => {
  if (!sets.length) return false;
  const rows = new Map(Array.from(container.querySelectorAll<HTMLTableRowElement>("tbody tr"))
    .map(row => [row.getAttribute("data-requirement-id"), row]));
  if (rows.size !== sets.length || !sets.every(set => rows.has(set.id))) return false;
  for (const set of sets) rows.get(set.id)!.cells[1]!.textContent = String(set.instructionCount);
  return true;
};

export const updateAarch64InstructionSets = (
  elementId: string,
  progress: Pick<ElfInstructionSetProgress, "stage" | "aarch64InstructionSets">
): void => {
  const container = document.getElementById(elementId);
  if (!container) return;
  if (progress.stage === "loading") {
    container.innerHTML = "";
    return;
  }
  if (!progress.aarch64InstructionSets) return;
  // Capture before replacing the DOM; the previous sort state is lost after innerHTML changes.
  const sortState = captureSortableTableState(container);
  if (!updateCounts(container, progress.aarch64InstructionSets)) {
    container.innerHTML = renderAarch64RequirementTable(progress.aarch64InstructionSets);
  }
  enhanceSortableTables(container);
  restoreSortableTableState(container, sortState);
};
