import { escapeHtmlText } from "../../html-utils.js";

const inventory = (caption: string, heading: string, rows: [string, number][]): string => {
  if (rows.length === 0) return "";
  return `<table class="table"><caption>${escapeHtmlText(caption)}</caption><thead><tr>` +
    `<th>${escapeHtmlText(heading)}</th><th class="peNumeric">Count</th></tr></thead><tbody>` +
    rows.map(([label, count]) => `<tr><td>${escapeHtmlText(label)}</td>` +
      `<td class="peNumeric">${count}</td></tr>`).join("") + `</tbody></table>`;
};

export const renderUnwindCounts = (caption: string, heading: string, counts: Record<string, number>): string =>
  inventory(caption, heading, Object.entries(counts)
    .sort(([left, leftCount], [right, rightCount]) =>
      rightCount - leftCount || left.localeCompare(right, "en", { numeric: true }))
    .map(([label, count]) => [label.replaceAll("_", " "), count]));

const binBoundary = (exponent: number): string => {
  if (exponent >= 30) return `${2 ** (exponent - 30)} GiB`;
  if (exponent >= 20) return `${2 ** (exponent - 20)} MiB`;
  if (exponent >= 10) return `${2 ** (exponent - 10)} KiB`;
  return `${2 ** exponent} B`;
};

/** Aggregate exact stored sizes into logarithmic bins instead of enumerating offsets. */
export const renderUnwindSizes = (caption: string, counts: Record<number, number>, heading = "Size range"): string => {
  const bins = new Map<number, number>();
  for (const [size, count] of Object.entries(counts)) {
    const exponent = Number(size) === 0 ? -1 : Math.floor(Math.log2(Number(size)));
    bins.set(exponent, (bins.get(exponent) ?? 0) + count);
  }
  return inventory(caption, heading, [...bins].sort(([left], [right]) => left - right)
    .map(([exponent, count]) => [exponent === -1 ? "0 bytes" :
      `${binBoundary(exponent)} to < ${binBoundary(exponent + 1)}`, count]));
};
