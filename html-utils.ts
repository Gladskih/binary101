"use strict";

import { toHex32 } from "./binary-utils.js";

export const escapeHtml = (input: unknown): string =>
  String(input)
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;");

export const renderDefinitionRow = (
  label: string,
  valueHtml: string,
  tooltip?: string | null
): string =>
  `<dt${tooltip ? ` title="${escapeHtml(tooltip)}"` : ""}>${label}</dt><dd>${valueHtml}</dd>`;

export const renderOptionChips = (
  selectedCode: number,
  options: Array<[number, string, string?]>
): string =>
  `<div class="optionsRow">${options
    .map(([code, label]) =>
      `<span class="opt ${code === selectedCode ? "sel" : "dim"}" title="${escapeHtml(
        `${label} (${toHex32(code, 4)})`
      )}">${label}</span>`
    )
    .join("")}
  </div>`;

export const renderFlagChips = (
  mask: number,
  flags: Array<[number, string, string?]>
): string =>
  `<div class="optionsRow">${flags
    .map(([bit, name, explanation]) => {
      const isSet = (mask & bit) !== 0;
      const label = explanation ? `${name} - ${explanation}` : name;
      const tooltip = `${label} (${toHex32(bit, 4)})`;
      return `<span class="opt ${isSet ? "sel" : "dim"}" title="${escapeHtml(tooltip)}">${name}</span>`;
    })
    .join("")}
  </div>`;

// Backwards-compatible aliases kept while refactoring callers.
export const safe = escapeHtml;
export const dd = renderDefinitionRow;
export const rowOpts = renderOptionChips;
export const rowFlags = renderFlagChips;
