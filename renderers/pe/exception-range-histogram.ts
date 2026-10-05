"use strict";

import type { PeExceptionDirectory } from "../../analyzers/pe/exception/types.js";

const numberLabel = (value: number): string => value.toLocaleString("en-US");

const boundaryLabel = (value: number): string => {
  if (value >= 2 ** 30) return `${value / 2 ** 30} GiB`;
  if (value >= 2 ** 20) return `${value / 2 ** 20} MiB`;
  if (value >= 2 ** 10) return `${value / 2 ** 10} KiB`;
  return numberLabel(value);
};

const countRangeLengths = (lengths: readonly number[]): number[] => {
  // PE RVAs are 32-bit: at most 32 power-of-two bins, independent of the file size.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-runtime_function
  const counts = Array<number>(32).fill(0);
  for (const length of lengths) {
    if (!Number.isInteger(length) || length <= 0 || length > 0xffffffff) continue;
    const index = Math.floor(Math.log2(length));
    counts[index] = counts[index]! + 1;
  }
  return counts;
};

// SVG layout: baseline y=214, 160px plot height and 20px right margin.
const renderCountAxis = (maximum: number, width: number, leftMargin: number): string =>
  [0, 0.25, 0.5, 0.75, 1].map(fraction => {
    const y = 214 - fraction * 160;
    return `<path class="rangeHistogram__grid" d="M${leftMargin} ${y}H${width - 20}"/>` +
      `<text class="rangeHistogram__tick" x="${leftMargin - 10}" y="${y + 4}" text-anchor="end">` +
      `${numberLabel(Math.round(maximum * fraction))}</text>`;
  }).join("");

const renderRangeBar = (count: number, exponent: number, x: number, maximum: number): string => {
  const height = count / maximum * 160;
  const lower = 2 ** exponent;
  const upper = 2 ** (exponent + 1) - 1;
  // Bars are 28px wide; counts sit 8px above them, lower-bound labels below the baseline.
  return `<g><title>${lower === upper
    ? numberLabel(lower)
    : `${numberLabel(lower)}–${numberLabel(upper)}`
  } bytes: ${numberLabel(count)} ranges</title>` +
    `<rect class="rangeHistogram__bar" x="${x}" y="${214 - height}" ` +
    `width="28" height="${height}" rx="2"/>` +
    `<text class="rangeHistogram__count" x="${x + 14}" y="${206 - height}" ` +
    `text-anchor="middle">${numberLabel(count)}</text>` +
    `<text class="rangeHistogram__tick" x="${x + 14}" y="238" ` +
    `text-anchor="middle">${boundaryLabel(lower)}</text></g>`;
};

const renderHistogramPlot = (counts: readonly number[]): string => {
  const first = counts.findIndex(count => count > 0);
  const last = counts.findLastIndex(count => count > 0);
  // Five count-axis ticks, with integer counts even for very small samples.
  const maximum = Math.ceil(Math.max(4, ...counts) / 4) * 4;
  // Compact default margin; reserve 7px per count-label character for larger tables.
  const leftMargin = Math.max(40, numberLabel(maximum).length * 7 + 10);
  // Reserve 46px per bin plus axis margins; allow mild scaling before horizontal scrolling.
  const width = Math.max(640, (last - first + 1) * 46 + leftMargin + 40);
  const step = (width - leftMargin - 40) / (last - first + 1);
  return `<div class="rangeHistogram__scroll">` +
    `<svg class="rangeHistogram__plot" xmlns="http://www.w3.org/2000/svg" ` +
    `style="min-width:${Math.max(640, width - 120)}px" ` +
    `viewBox="0 0 ${width} 280" role="img" aria-label="Histogram of code range lengths. ` +
    `Horizontal axis: bytes, grouped by powers of two. Vertical axis: number of ranges.">` +
    `<desc>${counts.slice(first, last + 1).map((count, index) =>
      `${numberLabel(2 ** (first + index))}–${numberLabel(2 ** (first + index + 1) - 1)} ` +
      `bytes: ${numberLabel(count)} ranges`
    ).join("; ")}</desc>` +
    `<text class="rangeHistogram__axis" x="${leftMargin}" y="22">Number of ranges</text>` +
    renderCountAxis(maximum, width, leftMargin) +
    counts.slice(first, last + 1).map((count, index) =>
      renderRangeBar(count, first + index, leftMargin + index * step + (step - 28) / 2, maximum)
    ).join("") +
    `<text class="rangeHistogram__axis" x="${width - 20}" y="270" ` +
    `text-anchor="end">Range length · power-of-two bins</text></svg></div>`;
};

export const renderExceptionRangeHistogram = (exception: PeExceptionDirectory): string => {
  if (!exception.rangeLengths?.length) {
    return `<p class="smallNote">Range length distribution is unavailable: ` +
      `no validated ranges with known lengths.</p>`;
  }
  const counts = countRangeLengths(exception.rangeLengths);
  const measured = counts.reduce((total, count) => total + count, 0);
  if (!measured) return `<p class="smallNote">No valid range lengths to plot.</p>`;
  const excluded = Math.max(0, exception.functionCount - measured);
  return `<figure class="rangeHistogram"><figcaption class="rangeHistogram__caption">` +
    `<strong>Range length distribution</strong>` +
    `<span>${numberLabel(measured)} measured ranges` +
    `${excluded ? ` · ${numberLabel(excluded)} entries excluded (invalid or unknown length)` : ""}` +
    `</span></figcaption>` + renderHistogramPlot(counts) +
    `<p class="rangeHistogram__note">Labels mark lower bounds. ` +
    `Each entry counts once. ` +
    `Ranges may cover part of a function; functions without .pdata entries are absent.</p></figure>`;
};
