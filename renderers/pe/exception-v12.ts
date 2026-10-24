import type { Amd64UnwindV12Statistics } from "../../analyzers/pe/exception/amd64/unwind-v12-types.js";
import { humanSize } from "../../binary-utils.js";
import { renderDefinitionRow } from "../../html-utils.js";
import { renderUnwindCounts, renderUnwindSizes } from "./unwind-inventories.js";

const largestSize = (label: string, counts: Record<number, number>): string => {
  const sizes = Object.keys(counts).map(Number);
  return sizes.length === 0 ? "" : renderDefinitionRow(label,
    humanSize(sizes.reduce((largest, size) => Math.max(largest, size), 0)));
};

export const renderExceptionV12 = (statistics: Amd64UnwindV12Statistics): string => {
  if (!statistics.blockCount) return "";
  return `<p class="smallNote">AMD64 UNWIND_INFO v1/v2 inventories count each unique referenced block once. ` +
    `Allocation sizes are explicit operations, not reconstructed function-frame sizes. ` +
    `Shared and chained blocks are not counted as independent function frames; ` +
    `decoded prefixes of incomplete blocks contribute to the inventories.</p><dl>` +
    renderDefinitionRow("UNWIND_INFO v1/v2 blocks summarized", String(statistics.blockCount)) +
    (statistics.incompleteBlockCount ? renderDefinitionRow("Blocks with incomplete operation decoding",
      String(statistics.incompleteBlockCount)) : "") +
    largestSize("Largest explicit stack allocation", statistics.allocationCounts) +
    largestSize("Largest prolog", statistics.prologSizeCounts) + `</dl>` +
    renderUnwindCounts("AMD64 v1/v2 unwind operations", "Operation", statistics.operationCounts) +
    renderUnwindCounts("Saved registers", "Register", statistics.registerCounts) +
    renderUnwindCounts("Frame registers", "Register", statistics.frameRegisterCounts) +
    renderUnwindSizes("Explicit stack allocation distribution", statistics.allocationCounts) +
    renderUnwindSizes("Saved-register stack displacement distribution", statistics.saveOffsetCounts) +
    renderUnwindSizes("Frame-pointer displacement distribution", statistics.frameOffsetCounts) +
    renderUnwindSizes("Hardware machine-frame sizes", statistics.machineFrameCounts);
};
