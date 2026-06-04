"use strict";

import type { ResourceTypeLibraryPreview } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";

const formatHex32 = (value: number): string => {
  if (value < 0) return String(value);
  // A 32-bit value contains 8 hexadecimal digits because each digit encodes 4 bits.
  return `0x${(value >>> 0).toString(16).padStart(8, "0")}`;
};

const renderHeaderFields = (typeLibrary: ResourceTypeLibraryPreview): string => {
  if (!typeLibrary.headerFields.length) return "";
  const rows = typeLibrary.headerFields
    .map(field =>
      `<tr><th scope="row">${escapeHtml(field.label)}</th><td>${escapeHtml(field.value)}</td></tr>`
    )
    .join("");
  return `<table class="table peResourceFieldTable"><tbody>${rows}</tbody></table>`;
};

const renderSegments = (typeLibrary: ResourceTypeLibraryPreview): string => {
  if (!typeLibrary.segments.length) return "";
  const rows = typeLibrary.segments
    .map(segment =>
      `<tr><td>${escapeHtml(segment.name)}</td><td class="mono peNumeric">${formatHex32(segment.offset)}</td>` +
      `<td class="mono peNumeric">${formatHex32(segment.length)}</td></tr>`
    )
    .join("");
  return `<table class="table peResourceNestedTable"><thead><tr>` +
    `<th>MSFT segment</th><th>Offset</th><th>Length</th></tr></thead><tbody>${rows}</tbody></table>`;
};

export const renderTypeLibraryPreview = (
  typeLibrary: ResourceTypeLibraryPreview | undefined
): string => {
  if (!typeLibrary) return "";
  return `<div class="smallNote"><b>${escapeHtml(typeLibrary.format)} type library</b></div>` +
    renderHeaderFields(typeLibrary) +
    renderSegments(typeLibrary);
};
