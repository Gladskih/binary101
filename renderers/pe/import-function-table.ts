"use strict";

import { escapeHtml } from "../../html-utils.js";
import {
  renderDirectIatRefsCells,
  renderDirectIatRefsHeaders,
  type DirectIatReferenceCounts
} from "./direct-iat-references.js";
import type { WinapiMetadataEntry } from "../../winapi-metadata-schema.js";

interface ImportFunctionRow {
  ordinal?: number;
  hint?: number;
  name?: string;
  winapiMetadata?: WinapiMetadataEntry;
}

const renderWinapiMetadataCell = (entry: WinapiMetadataEntry | undefined): string => {
  if (!entry) return `<td class="winapiMetadataCell">-</td>`;
  const callingConvention = entry.variadic
    ? `${entry.callingConvention}, variadic`
    : entry.callingConvention;
  return `<td class="winapiMetadataCell">` +
    `<span class="winapiMetadataNamespace">${escapeHtml(entry.namespace ?? "Win32Metadata")}</span>` +
    `<code class="winapiMetadataSignature">${escapeHtml(entry.signature)}</code>` +
    `<span class="winapiMetadataConvention">${escapeHtml(callingConvention)}</span>` +
    `</td>`;
};

const renderImportName = (fn: ImportFunctionRow): string =>
  fn.name
    ? escapeHtml(fn.name)
    : fn.ordinal != null
      ? `ORD ${fn.ordinal}`
      : "-";

const renderFunctionRow = (
  fn: ImportFunctionRow,
  functionIndex: number,
  iatRva: number,
  counts: ReadonlyMap<number, DirectIatReferenceCounts>,
  entrySize: number
): string => {
  const directIatRefs = renderDirectIatRefsCells(counts, iatRva, functionIndex, entrySize);
  const hint = fn.hint != null ? String(fn.hint) : "-";
  return `<tr><td>${functionIndex + 1}</td><td>${hint}</td><td>${renderImportName(fn)}</td>` +
    `${renderWinapiMetadataCell(fn.winapiMetadata)}${directIatRefs}</tr>`;
};

export const renderImportFunctionTable = (
  functions: ImportFunctionRow[],
  sortKey: string,
  iatRva: number,
  counts: ReadonlyMap<number, DirectIatReferenceCounts>,
  entrySize: number
): string => {
  const rows = functions.map((fn, index) =>
    renderFunctionRow(fn, index, iatRva, counts, entrySize));
  return `<div class="tableWrap"><table class="table" data-sort-state-key="${escapeHtml(sortKey)}" ` +
    `style="margin-top:.35rem"><thead><tr><th>#</th><th>Hint</th><th>Name / Ordinal</th>` +
    `<th>WinAPI</th>${renderDirectIatRefsHeaders()}</tr></thead><tbody>` +
    `${rows.join("")}</tbody></table></div>`;
};
