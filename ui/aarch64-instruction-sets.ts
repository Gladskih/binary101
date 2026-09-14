import type { ElfInstructionSetProgress } from "../analyzers/elf/disassembly-types.js";
import { renderAarch64RequirementTable } from "../renderers/aarch64-instruction-sets.js";
import {
  captureSortableTableState, enhanceSortableTables, restoreSortableTableState
} from "./sortable-tables.js";

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
  container.innerHTML = renderAarch64RequirementTable(progress.aarch64InstructionSets);
  enhanceSortableTables(container);
  restoreSortableTableState(container, sortState);
};
