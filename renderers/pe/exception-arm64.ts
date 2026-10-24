import type { Arm64PackedStatistics } from "../../analyzers/pe/exception/arm64-packed-types.js";
import type { Arm64UnwindStatistics } from "../../analyzers/pe/exception/arm64-unwind-types.js";
import { humanSize } from "../../binary-utils.js";
import { renderDefinitionRow } from "../../html-utils.js";
import { renderUnwindCounts, renderUnwindSizes } from "./unwind-inventories.js";

export const renderArm64PackedStatistics = (statistics: Arm64PackedStatistics): string => {
  const largest = Object.keys(statistics.frameSizeCounts)
    .reduce((maximum, value) => Math.max(maximum, Number(value)), -1);
  if (largest < 0) return "";
  const modes = ["Unchained, LR not saved", "Unchained, LR saved", "Frame chain with signed LR", "Frame chain"];
  return `<p class="smallNote">ARM64 packed frame sizes include fixed local and save areas, ` +
    `but exclude dynamic alloca storage. Each packed .pdata entry counts once, including fragments; ` +
    `registers describe encoded saves, not instructions executed inside a fragment.</p><dl>` +
    renderDefinitionRow("Largest encoded packed frame", humanSize(largest)) +
    renderDefinitionRow("Packed fragments", String(statistics.fragmentCount)) +
    renderDefinitionRow("Packed entries with parameter homes", String(statistics.homesParametersCount)) + `</dl>` +
    renderUnwindCounts("ARM64 packed return and frame modes", "Mode", Object.fromEntries(
      Object.entries(statistics.returnKinds).map(([mode, count]) => [modes[Number(mode)]!, count]))) +
    renderUnwindCounts("ARM64 packed encoded register saves", "Register", statistics.registerCounts) +
    renderUnwindSizes("ARM64 packed frame-size distribution", statistics.frameSizeCounts);
};

const scalableSaves = (counts: Record<string, number>): Record<string, number> => Object.fromEntries(
  Object.entries(counts).map(([key, count]) => {
    const [unit, coefficient] = key.split(":");
    return [`${coefficient} × ${unit === "vectorLengths" ? "VL" : "(VL / 8)"}`, count];
  }));

export const renderArm64UnwindStatistics = (statistics: Arm64UnwindStatistics): string => {
  if (!statistics.blockCount) return "";
  return `<p class="smallNote">ARM64 .xdata inventories count each unique referenced code block once. ` +
    `Shared prolog/epilog tails count once; padding is excluded. ` +
    `Allocation operands and pre-index adjustments are not reconstructed frame sizes. ` +
    `SVE sizes retain their vector-length units (VL); no runtime vector length is assumed.</p><dl>` +
    renderDefinitionRow("ARM64 .xdata blocks decoded", String(statistics.blockCount)) +
    (statistics.incompleteBlockCount ? renderDefinitionRow("ARM64 blocks with decode gaps",
      String(statistics.incompleteBlockCount)) : "") + `</dl>` +
    renderUnwindCounts("ARM64 .xdata unwind operations", "Operation", statistics.operationCounts) +
    renderUnwindCounts("ARM64 .xdata saved registers", "Register", statistics.registerCounts) +
    renderUnwindSizes("ARM64 explicit stack allocations", statistics.allocationCounts) +
    renderUnwindSizes("ARM64 stack adjustments folded into saves", statistics.preIndexAdjustmentCounts) +
    renderUnwindSizes("ARM64 saved-register stack displacements", statistics.saveOffsetCounts) +
    renderUnwindSizes("ARM64 frame-pointer displacements", statistics.frameOffsetCounts) +
    renderUnwindCounts("ARM64 scalable stack allocations", "Vector lengths", statistics.scalableAllocationCounts) +
    renderUnwindCounts("ARM64 scalable saved-register displacements", "Displacement", scalableSaves(statistics.scalableSaveCounts));
};
