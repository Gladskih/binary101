"use strict";

import { escapeHtml } from "../../html-utils.js";
import type {
  PeClrAdditionalCell, PeClrMetadataTables, PeClrMethodSignature
} from "../../analyzers/pe/clr/types.js";

export const renderSignatureIssues = (issues: string[] | undefined): string =>
  issues?.length
    ? `<ul class="smallNote">${issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`
    : "";

export const methodSignatureText = (signature: PeClrMethodSignature): string => {
  if (signature.callingConvention === 0x06) return signature.returnType ?? "?"; // ECMA-335 II.23.2.4 FIELD.
  const types = signature.parameterTypes.map(type => type ?? "?");
  if (signature.sentinelIndex != null) types.splice(signature.sentinelIndex, 0, "...");
  return `${signature.returnType ?? "?"} (${types.join(", ")})`;
};

export const renderMetadataCell = (cell: PeClrAdditionalCell): string => {
  if (cell == null) return "-";
  if (typeof cell !== "object") return escapeHtml(String(cell));
  if (Array.isArray(cell)) {
    // Local preview budget: retain full blob bytes in analysis but format only the first 64.
    return escapeHtml(cell.slice(0, 64).map(byte => byte.toString(16).padStart(2, "0")).join(" ")) +
      (cell.length > 64 ? ` … (${cell.length} bytes)` : "");
  }
  if ("table" in cell) {
    return escapeHtml(`${cell.table} #${cell.row}${cell.valid ? "" : " (invalid)"}`);
  }
  return renderSignatureCell(cell);
};

const renderSignatureCell = (
  cell: Exclude<PeClrAdditionalCell, number | string | null | number[] | { table: string }>
): string => {
  return escapeHtml("parameterTypes" in cell ? methodSignatureText(cell)
    : "types" in cell ? cell.types.join(", ") : cell.type ?? "?") + renderSignatureIssues(cell.issues);
};

const renderAdditionalRows = (
  rows: Record<string, PeClrAdditionalCell>[],
  columns: string[]
): string =>
  rows.slice(0, 80).map((row, index) =>
    `<tr><td class="peNumeric">${index + 1}</td>` + columns.map(column => {
      const value = row[column] ?? null;
      return `<td${typeof value === "number" ? ' class="peNumeric"' : ""}>` +
        `${renderMetadataCell(value)}</td>`;
    }).join("") + "</tr>"
  ).join("");

const renderAdditionalTable = (
  table: NonNullable<PeClrMetadataTables["additionalTables"]>[number],
  name: string
): string => {
  const firstRow = table.rows[0];
  if (!firstRow) return "";
  const columns = Object.keys(firstRow);
  // Same display budget as the existing CLR tables; slice before formatting rows.
  return `<details><summary>${escapeHtml(name)} (${table.rows.length})</summary>` +
    (table.rows.length > 80 ? `<p class="smallNote">Showing first 80 of ${table.rows.length} rows.</p>` : "") +
    `<div class="tableWrap"><table class="table"><thead><tr><th>RID</th>` +
    columns.map(column => `<th>${escapeHtml(column)}</th>`).join("") +
    `</tr></thead><tbody>${renderAdditionalRows(table.rows, columns)}</tbody></table></div></details>`;
};

export const renderAdditionalMetadataTables = (metadata: PeClrMetadataTables): string =>
  (metadata.additionalTables ?? []).map(table => renderAdditionalTable(table,
    metadata.rowCounts.find(count => count.tableId === table.tableId)?.name ?? `Table ${table.tableId}`
  )).join("");

export const renderFieldsAndMembers = (metadata: PeClrMetadataTables): string =>
  renderAdditionalTable({ tableId: 4, rows: (metadata.fields ?? []).map(field => ({
    Name: field.name, Flags: field.flags, Signature: field.signature ?? null
  })) }, "Field definitions") +
  renderAdditionalTable({ tableId: 10, rows: metadata.memberRefs.map(member => ({
    Parent: member.parentName ?? member.parent, Name: member.name, Signature: member.signature ?? null
  })) }, "Member references");
