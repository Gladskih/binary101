import type { ArmntPackedStatistics } from "../../analyzers/pe/exception/armnt-packed-types.js";
import type { ArmntOpcodeStatistics } from "../../analyzers/pe/exception/armnt-opcode-types.js";
import { humanSize } from "../../binary-utils.js";
import { escapeHtmlText, renderDefinitionRow } from "../../html-utils.js";

const renderDistribution = (caption: string, label: string, entries: [string, number][]): string => {
  const rows = entries.filter(([, count]) => count > 0).sort(([left, leftCount], [right, rightCount]) =>
    rightCount - leftCount || left.localeCompare(right, "en", { numeric: true }));
  if (!rows.length) return "";
  return `<table class="table"><caption>${caption}</caption><thead><tr><th>${label}</th>` +
    `<th class="peNumeric">Entries</th></tr></thead><tbody>` + rows.map(([name, count]) =>
    `<tr><td>${escapeHtmlText(name)}</td><td class="peNumeric">${count}</td></tr>`).join("") + `</tbody></table>`;
};

const renderFlags = (statistics: ArmntPackedStatistics): string => ([
  ["Parameter homes", statistics.homesParametersCount],
  ["LR saves", statistics.savesLinkRegisterCount],
  ["Frame chains (r11/LR)", statistics.frameChainCount],
  ["Prolog adjustments folded into pushes", statistics.prologFoldingCount],
  ["Epilog adjustments folded into pops", statistics.epilogFoldingCount]
] as const).filter(([, count]) => count > 0).map(([label, count]) => renderDefinitionRow(label, String(count))).join("");

export const renderArmntPackedStatistics = (statistics: ArmntPackedStatistics): string => {
  const total = Object.values(statistics.returnKinds).reduce((sum, count) => sum + count, 0);
  if (!total) return "";
  const largest = Object.keys(statistics.stackAdjustments)
    .reduce((maximum, size) => Math.max(maximum, Number(size)), 0);
  return `<dl>` + renderDefinitionRow("Packed .pdata entries", String(total)) + renderFlags(statistics) +
    (largest > 0 ? renderDefinitionRow("Largest encoded local stack adjustment", humanSize(largest)) : "") +
    `</dl><p class="smallNote">Register groups describe the explicit nonvolatile group; ` +
    `parameter homes, LR saves and frame chains are counted separately. Stack adjustments exclude ` +
    `those register saves and parameter homes.</p>` +
    renderDistribution("Packed return modes", "Return", [
      ["POP PC", statistics.returnKinds.popPc], ["16-bit branch", statistics.returnKinds.branch16],
      ["32-bit branch", statistics.returnKinds.branch32], ["No epilog", statistics.returnKinds.noEpilog]
    ]) + renderDistribution("Encoded nonvolatile register groups", "Group", Object.entries(statistics.registerGroups));
};

export const renderArmntOpcodeStatistics = (statistics: ArmntOpcodeStatistics): string => {
  if (!Object.keys(statistics.opcodeCounts).length && !statistics.incompleteSequenceCount) return "";
  const largest = Object.keys(statistics.stackAdjustments)
    .reduce((maximum, size) => Math.max(maximum, Number(size)), 0);
  const operations = Object.entries(statistics.opcodeCounts).map(([name, count]) => [name, count] as [string, number]);
  return `<h3>ARMNT .xdata unwind operations</h3><dl>` +
    renderDefinitionRow("Unique opcode sequences with incomplete decoding", String(statistics.incompleteSequenceCount)) +
    renderDefinitionRow("Integer registers restored", String(statistics.integerRegisterPopCount)) +
    renderDefinitionRow("Floating point registers restored", String(statistics.floatingRegisterPopCount)) +
    renderDefinitionRow("Frame pointer restores", String(statistics.framePointerRestores)) +
    renderDefinitionRow("Return address loads", String(statistics.returnAddressLoads)) +
    (largest > 0 ? renderDefinitionRow("Largest explicit stack adjustment", humanSize(largest)) : "") +
    `</dl>` + renderDistribution("Unwind operation inventory", "Operation", operations) +
    renderDistribution("ARMNT special marker operations", "Marker", Object.entries(statistics.specialMarkers)) +
    renderDistribution("Explicit stack adjustments", "Bytes", Object.entries(statistics.stackAdjustments)
      .map(([size, count]) => [size, count]));
};
