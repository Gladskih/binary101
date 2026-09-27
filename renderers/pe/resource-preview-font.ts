"use strict";

import type { ResourceFontDirectory, ResourceFontPreview } from "../../analyzers/pe/resources/preview/font-types.js";
import { escapeHtml } from "../../html-utils.js";

const fontCells = (font: ResourceFontPreview): string => [
  font.faceName, font.deviceName || "-", `${font.pointSize} pt`, String(font.weight),
  [font.italic ? "italic" : "", font.underline ? "underline" : "",
    font.strikeOut ? "strikeout" : ""].filter(Boolean).join(", ") || "-",
  String(font.charset), `${font.pixelWidth}×${font.pixelHeight}`,
  `${font.horizontalResolution}×${font.verticalResolution}`, `${font.firstChar}–${font.lastChar}`,
  `0x${font.version.toString(16)}`, String(font.fileSize)
].map((value, index) => `<td${index >= 2 ? ' class="mono peNumeric"' : ""}>${escapeHtml(value)}</td>`).join("");

const fontTable = (rows: string): string =>
  `<div style="overflow-x:auto"><table class="table peResourceNestedTable"><thead><tr>` +
  `<th>FONT ID</th><th>Face</th><th>Device</th><th>Size</th><th>Weight</th><th>Attributes</th>` +
  `<th>Charset</th><th>Pixels</th><th>DPI</th><th>Characters</th><th>FNT version</th>` +
  `<th>File bytes</th></tr></thead><tbody>${rows}</tbody></table></div>`;

export const renderFontDirectoryPreview = (directory: ResourceFontDirectory): string =>
  `<p>FONTDIR: ${directory.entries.length} fonts; ${directory.headerSize}-byte entry prefix.</p>` +
  fontTable(directory.entries.map(entry =>
    `<tr><td class="mono peNumeric">FONT #${entry.ordinal}</td>${fontCells(entry.font)}</tr>`
  ).join(""));

export const renderLegacyFontPreview = (font: ResourceFontPreview): string =>
  fontTable(`<tr><td>-</td>${fontCells(font)}</tr>`) +
  `<p class="smallNote">${escapeHtml(font.copyright)}</p>`;
