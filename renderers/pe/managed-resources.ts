"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";
import type {
  PeClrManagedResourceEntry, PeClrManagedResourceValue
} from "../../analyzers/pe/clr/managed-resource-types.js";
import { renderPreviewCell, renderPreviewSummary } from "./resource-preview-cell.js";
import {
  renderAutoPagedSortableTable, type PagedSortableTableModel
} from "../paged-sortable-table.js";

const renderWarnings = (issues: string[] | undefined): string => issues?.length
  ? `<ul class="smallNote" style="color:var(--warn-fg)">` +
    issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("") + `</ul>` : "";

const implementationName = (
  entry: PeClrManagedResourceEntry, clr: PeClrHeader
): string | null | undefined => {
  const rows = entry.implementation.table === "File" ? clr.meta?.tables?.files :
    entry.implementation.table === "AssemblyRef" ? clr.meta?.tables?.assemblyRefs : undefined;
  return rows?.find(row => row.row === entry.implementation.row)?.name;
};

const implementationText = (entry: PeClrManagedResourceEntry, clr: PeClrHeader): string => {
  const index = entry.implementation;
  if (index.raw === 0) return "-";
  const name = implementationName(entry, clr);
  return `${index.table} #${index.row}${name ? `: ${name}` : ""}${index.valid ? "" : " (invalid)"}`;
};

const contentText = (entry: PeClrManagedResourceEntry): string => entry.entries
  ? `.resources (${entry.entries.length} entries)` : renderPreviewSummary(entry);

const renderResourceDetails = (entry: PeClrManagedResourceEntry): string => {
  const preview = entry.previewKind ? renderPreviewCell(entry) : "";
  const values = entry.entries?.length ? renderAutoPagedSortableTable(
    createManagedResourceValueTableModel(entry.entries, entry.row)
  ) : "";
  const issues = renderWarnings(entry.issues);
  return preview || values || issues
    ? `<tr class="clrManagedResourceDetailRow"><td colspan="7">` +
      `<div class="clrManagedResourcesTable__detailContent">${preview}${values}${issues}</div></td></tr>`
    : "";
};

const resourceCells = (entry: PeClrManagedResourceEntry, clr: PeClrHeader): string[] => [
  entry.name ?? "(unnamed resource)", entry.storage,
  `${entry.flags === 1 ? "Public" : entry.flags === 2 ? "Private" : "Unknown"} (${hex(entry.flags, 8)})`,
  hex(entry.offset, 8), entry.size == null ? "-" : humanSize(entry.size),
  implementationText(entry, clr), contentText(entry)
];

export const createManagedResourceTableModel = (clr: PeClrHeader): PagedSortableTableModel => {
  const entries = clr.managedResources?.entries ?? [];
  return {
    id: "pe-clr-managed-resources", pageSize: 50, rowCount: entries.length,
    columns: ["Resource", "Storage", "Flags", "Offset", "Size", "Implementation", "Content"]
      .map(label => ({ label, ...["Offset", "Size"].includes(label) ? { className: "peNumeric" } : {} })),
    rowAt: index => {
      const entry = entries[index];
      return entry ? {
        className: "clrManagedResourcesTable__row",
        cells: resourceCells(entry, clr).map((html, column) => ({ html: escapeHtml(html),
          ...[3, 4].includes(column) ? { className: "peNumeric" } : {} })),
        additionalRowsHtml: renderResourceDetails(entry)
      } : null;
    },
    sortValueAt: (index, column) => {
      const entry = entries[index];
      if (!entry) return "";
      if (column === 3) return String(entry.offset);
      if (column === 4) return entry.size == null ? "" : String(entry.size);
      return resourceCells(entry, clr)[column] ?? "";
    },
    tableClassName: "clrManagedResourcesTable"
  };
};

const valueText = (value: PeClrManagedResourceValue): string => value.opaque
  ? "Opaque serialized data" : value.value === null
    ? value.issues?.length ? "Unavailable" : "null"
    : String(value.value).length > 1024 ? `${String(value.value).slice(0, 1024)}… (display capped)`
      : String(value.value);

const renderValuePreview = (value: PeClrManagedResourceValue): string => {
  if (!value.previewKind) return "";
  const source = value.textPreview ??
    (typeof value.value === "string" ? value.value.slice(0, 32 * 1024) : null);
  return renderPreviewCell({ ...value, ...(source != null ? { textPreview: source } : {}) });
};

export const createManagedResourceValueTableModel = (
  values: PeClrManagedResourceValue[], resourceRow: number
): PagedSortableTableModel => ({
  id: `pe-clr-managed-resource-values-${resourceRow}`, pageSize: 50, rowCount: values.length,
  columns: [{ label: "Entry" }, { label: "Type" }, { label: "Value" }],
  rowAt: index => {
    const value = values[index];
    if (!value) return null;
    const preview = renderValuePreview(value);
    const detail = preview + renderWarnings(value.issues);
    return {
      cells: [value.name, value.type, preview ? "See preview" : valueText(value)]
        .map(html => ({ html: escapeHtml(html) })),
      ...(detail ? { additionalRowsHtml:
        `<tr class="clrManagedResourceValuePreviewRow"><td colspan="3">${detail}</td></tr>` } : {})
    };
  },
  sortValueAt: (index, column) => {
    const value = values[index];
    return value ? [value.name, value.type, valueText(value)][column] ?? "" : "";
  },
  tableClassName: "clrManagedResourceValuesTable"
});

export const getManagedResourceTableModel = (
  clr: PeClrHeader | null | undefined, id: string
): PagedSortableTableModel | null => {
  if (!clr?.managedResources) return null;
  if (id === "pe-clr-managed-resources") return createManagedResourceTableModel(clr);
  const match = /^pe-clr-managed-resource-values-(\d+)$/u.exec(id);
  const resource = match && clr.managedResources.entries.find(entry => entry.row === Number(match[1]));
  return resource?.entries ? createManagedResourceValueTableModel(resource.entries, resource.row) : null;
};

export const renderManagedResources = (clr: PeClrHeader, out: string[]): void => {
  if (!clr.managedResources) return;
  out.push(`<details style="margin-top:.35rem" open>` +
    `<summary>Managed resources (${clr.managedResources.entries.length})</summary>` +
    `<p class="smallNote">CLR ManifestResource payloads, separate from the PE .rsrc tree. ` +
    `Custom serialized objects are shown as opaque data.</p>` +
    `<div class="clrManagedResources">` +
    renderAutoPagedSortableTable(createManagedResourceTableModel(clr)) + `</div>` +
    renderWarnings(clr.managedResources.issues) + `</details>`);
};
