import type { Amd64UnwindV3Statistics } from "../../analyzers/pe/exception/amd64/unwind-v3-types.js";
import { humanSize } from "../../binary-utils.js";
import { renderDefinitionRow } from "../../html-utils.js";
import { renderUnwindCounts, renderUnwindSizes } from "./unwind-inventories.js";

const renderLargest = (label: string, counts: Record<number, number>): string => {
  const sizes = Object.keys(counts).map(Number);
  return sizes.length === 0 ? "" : renderDefinitionRow(label,
    humanSize(sizes.reduce((largest, size) => Math.max(largest, size), 0)));
};

export const renderExceptionV3 = (statistics: Amd64UnwindV3Statistics): string => {
  if (statistics.blockCount === 0) return "";
  const extrema = renderLargest("Largest explicit stack allocation", statistics.allocationCounts) +
    renderLargest("Largest prolog", statistics.prologSizeCounts);
  return `<p class="smallNote">UNWIND_INFO v3 is a preview format supporting Intel APX. ` +
    `Inventories count distinct referenced winding-operation records in each block; ` +
    `shared prolog and epilog references count once.</p>` +
    (extrema ? `<dl>${extrema}</dl>` : "") +
    renderUnwindCounts("Winding operations", "Operation", statistics.operationCounts) +
    renderUnwindCounts("Registers referenced by winding operations", "Register", statistics.registerCounts) +
    renderUnwindSizes("Explicit stack allocation distribution", statistics.allocationCounts, "Allocation size") +
    renderUnwindCounts("OS-defined canonical frame types", "Frame type", Object.fromEntries(
      Object.entries(statistics.canonicalFrameTypeCounts).map(([type, count]) => [`Type ${type}`, count])));
};
