"use strict";

import { escapeHtml } from "../../html-utils.js";
import { renderMetadataValue } from "./clr-metadata-values.js";
import { createClrTableModel } from "./clr-table-model.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
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
    return escapeHtml(cell.map(byte => byte.toString(16).padStart(2, "0")).join(" "));
  }
  if ("table" in cell) {
    return escapeHtml(`${cell.table} #${cell.row}${cell.valid ? "" : " (invalid)"}`);
  }
  if ("kind" in cell) return renderMetadataValue(cell) + renderSignatureIssues(cell.issues);
  return renderSignatureCell(cell);
};

const renderSignatureCell = (
  cell: Exclude<PeClrAdditionalCell, number | string | null | number[] | { table: string } | { kind: string }>
): string => {
  return escapeHtml("parameterTypes" in cell ? methodSignatureText(cell)
    : "types" in cell ? cell.types.join(", ") : cell.type ?? "?") + renderSignatureIssues(cell.issues);
};

const additionalTableModel = (
  rows: Record<string, PeClrAdditionalCell>[],
  name: string
): PagedSortableTableModel => {
  const firstRow = rows[0] ?? {};
  const columns = Object.keys(firstRow);
  return createClrTableModel(name, ["RID", ...columns], rows.length, index => {
    const row = rows[index];
    return row ? [String(index + 1), ...columns.map(column => renderMetadataCell(row[column] ?? null))] : null;
  });
};

export const renderAdditionalMetadataTables = (metadata: PeClrMetadataTables): string =>
  (metadata.additionalTables ?? []).filter(table => table.rows.length).map(table => renderTableModel(table.rows,
    metadata.rowCounts.find(count => count.tableId === table.tableId)?.name ?? `Table ${table.tableId}`
  )).join("");

const renderTableModel = (rows: Record<string, PeClrAdditionalCell>[], name: string): string =>
  rows.length ? `<details><summary>${escapeHtml(name)} (${rows.length})</summary>` +
    renderAutoPagedSortableTable(additionalTableModel(rows, name)) + "</details>" : "";

export const renderFieldsAndMembers = (metadata: PeClrMetadataTables): string =>
  renderTableModel((metadata.fields ?? []).map(field => ({
    Name: field.name, Flags: field.flags, Signature: field.signature ?? null
  })), "Field definitions") +
  renderTableModel(metadata.memberRefs.map(member => ({
    Parent: member.parentName ?? member.parent, Name: member.name, Signature: member.signature ?? null
  })), "Member references");

export const createAdditionalMetadataTableModels = (metadata: PeClrMetadataTables): PagedSortableTableModel[] => [
  ...(metadata.additionalTables ?? []).map(table => additionalTableModel(table.rows,
    metadata.rowCounts.find(count => count.tableId === table.tableId)?.name ?? `Table ${table.tableId}`)),
  additionalTableModel((metadata.fields ?? []).map(field => ({
    Name: field.name, Flags: field.flags, Signature: field.signature ?? null
  })), "Field definitions"),
  additionalTableModel(metadata.memberRefs.map(member => ({
    Parent: member.parentName ?? member.parent, Name: member.name, Signature: member.signature ?? null
  })), "Member references")
];
