import type { Amd64UnwindV3Statistics } from "../../analyzers/pe/exception/amd64/unwind-v3-types.js";
import { humanSize } from "../../binary-utils.js";
import { escapeHtmlText, renderDefinitionRow } from "../../html-utils.js";

const renderInventory = (caption: string, heading: string, rows: [string, number][]): string => {
  if (rows.length === 0) return "";
  return `<table class="table"><caption>${caption}</caption><thead><tr><th>${heading}</th>` +
    `<th class="peNumeric">Count</th></tr></thead><tbody>` +
    rows.map(([label, count]) => `<tr><td>${escapeHtmlText(label)}</td>` +
      `<td class="peNumeric">${count}</td></tr>`).join("") + `</tbody></table>`;
};

const frequencyRows = (counts: Record<string, number>): [string, number][] => Object.entries(counts)
  .sort(([left, leftCount], [right, rightCount]) =>
    rightCount - leftCount || left.localeCompare(right, "en", { numeric: true }));

const renderLargest = (label: string, counts: Record<number, number>): string => {
  const sizes = Object.keys(counts).map(Number);
  return sizes.length === 0 ? "" : renderDefinitionRow(label,
    humanSize(sizes.reduce((largest, size) => Math.max(largest, size), 0)));
};

const binBoundary = (exponent: number): string => {
  if (exponent >= 30) return `${2 ** (exponent - 30)} GiB`;
  if (exponent >= 20) return `${2 ** (exponent - 20)} MiB`;
  if (exponent >= 10) return `${2 ** (exponent - 10)} KiB`;
  return `${2 ** exponent} B`;
};

const allocationBins = (counts: Record<number, number>): [string, number][] => {
  const bins = new Map<number, number>();
  for (const [size, count] of Object.entries(counts)) {
    const exponent = Number(size) === 0 ? -1 : Math.floor(Math.log2(Number(size)));
    bins.set(exponent, (bins.get(exponent) ?? 0) + count);
  }
  return [...bins].sort(([left], [right]) => left - right)
    .map(([exponent, count]) => [exponent === -1 ? "0 bytes" :
      `${binBoundary(exponent)} to < ${binBoundary(exponent + 1)}`, count]);
};

export const renderExceptionV3 = (statistics: Amd64UnwindV3Statistics): string => {
  if (statistics.blockCount === 0) return "";
  const extrema = renderLargest("Largest explicit stack allocation", statistics.allocationCounts) +
    renderLargest("Largest prolog", statistics.prologSizeCounts);
  return `<p class="smallNote">UNWIND_INFO v3 is a preview format supporting Intel APX. ` +
    `Inventories count distinct referenced winding-operation records in each block; ` +
    `shared prolog and epilog references count once.</p>` +
    (extrema ? `<dl>${extrema}</dl>` : "") +
    renderInventory("Winding operations", "Operation", frequencyRows(statistics.operationCounts)
      .map(([opcode, count]) => [opcode.replaceAll("_", " "), count])) +
    renderInventory("Registers referenced by winding operations", "Register", frequencyRows(statistics.registerCounts)) +
    renderInventory("Explicit stack allocation distribution", "Allocation size", allocationBins(statistics.allocationCounts)) +
    renderInventory("OS-defined canonical frame types", "Frame type", frequencyRows(statistics.canonicalFrameTypeCounts)
      .map(([type, count]) => [`Type ${type}`, count]));
};
