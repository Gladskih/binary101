import { escapeHtmlText } from "../html-utils.js";
import { hex, humanSize } from "../binary-utils.js";
import type { EmbeddedResource, EmbeddedResourceAnalysis, EmbeddedResourceEntry }
  from "../analyzers/embedded-resources/types.js";
import { resolveResourcePayload } from "../analyzers/embedded-resources/payload.js";
import { renderPreviewCell } from "./pe/resource-preview-cell.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./elf/collapsible-section.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "./paged-sortable-table.js";

const notices = (issues: string[]): string => issues.length ?
  `<ul class="smallNote">${issues.map(issue => `<li>${escapeHtmlText(issue)}</li>`).join("")}</ul>` : "";

const fields = (value: object, excluded: string[]): string =>
  `<table class="table"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>` +
  Object.entries(value).filter(([key]) => !excluded.includes(key)).map(([key, item]) =>
    `<tr><th scope="row">${escapeHtmlText(key)}</th><td>${escapeHtmlText(JSON.stringify(item,
      (_name, nested: unknown) => typeof nested === "bigint" ? nested.toString() : nested))}</td></tr>`
  ).join("") + "</tbody></table>";

const entryCells = (entry: EmbeddedResourceEntry, index: number, format: EmbeddedResource["format"]): string[] => {
  const payload = resolveResourcePayload(format, entry);
  return [String(index), entry.name || "/", entry.parent === null ? "—" : String(entry.parent),
    payload ? "File" : "Directory", payload ? hex(payload.offset) : "—",
    payload ? humanSize(payload.size) : "—", payload ? humanSize(payload.uncompressedSize) : "—",
    payload?.compression ?? "—"];
};

const numericColumns = new Set([0, 2, 4, 5, 6]);

const sortValue = (entry: EmbeddedResourceEntry, index: number, column: number, format: EmbeddedResource["format"]): string => {
  const value = ({ 0: index, 2: entry.parent ?? "", 4: entry.payload?.offset,
    5: entry.payload?.size, 6: entry.payload?.uncompressedSize ?? entry.payload?.size } as
    Record<number, number | string | undefined>)[column];
  return value === undefined ? entryCells(entry, index, format)[column] ?? "" : String(value);
};

export const createEmbeddedResourceTableModel = (analysis: EmbeddedResourceAnalysis,
  bundleIndex: number): PagedSortableTableModel => {
  const resource = analysis.bundles[bundleIndex]!.resource;
  const entries = resource.entries;
  return {
    id: `embedded-resources-${bundleIndex}`, pageSize: 50, rowCount: entries.length,
    columns: ["Index", "Name", "Parent", "Kind", "File offset", "Stored", "Uncompressed", "Compression"]
      .map((label, column) => ({ label, ...(numericColumns.has(column) ? { className: "peNumeric" } : {}) })),
    rowAt: index => {
      const entry = entries[index];
      if (!entry) return null;
      const download = entry.payload ? `<button type="button" data-embedded-resource-bundle="${bundleIndex}" ` +
        `data-embedded-resource-entry="${index}">Download</button>` : "";
      const preview = entry.preview ? renderPreviewCell(entry.preview) : "";
      return { className: "embeddedResources__row",
        cells: entryCells(entry, index, resource.format).map((value, column) => ({ html: escapeHtmlText(value),
        ...(numericColumns.has(column) ? { className: "peNumeric" } : {}) })),
        additionalRowsHtml: `<tr class="embeddedResources__detail"><td colspan="8">` +
          `<div class="embeddedResources__content">${download}${preview}` +
          `<details><summary>Structure fields</summary>${fields(entry, ["name", "parent", "payload", "preview"])}` +
          `</details></div></td></tr>` };
    },
    sortValueAt: (index, column) => entries[index] ? sortValue(entries[index]!, index, column, resource.format) : "",
    tableClassName: "embeddedResources__table"
  };
};

export const getEmbeddedResourceTableModel = (analysis: EmbeddedResourceAnalysis | undefined,
  id: string): PagedSortableTableModel | null => {
  const match = /^embedded-resources-(\d+)$/u.exec(id);
  return analysis?.bundles[Number(match?.[1])] ? createEmbeddedResourceTableModel(analysis, Number(match![1])) : null;
};

export const renderEmbeddedResources = (analysis: EmbeddedResourceAnalysis | undefined): string => {
  if (!analysis) return "";
  return renderElfSectionStart("Qt / GLib embedded resources") + notices(analysis.issues) +
    `<div class="embeddedResources">` +
    analysis.bundles.map((bundle, index) => `<h3>${escapeHtmlText(bundle.resource.format)} at ${hex(bundle.offset)}</h3>` +
      `<p>${escapeHtmlText(bundle.evidence.join("; "))}</p>` + notices(bundle.issues) +
      `<details><summary>Container fields</summary>${fields(bundle.resource, ["entries"])}</details>` +
      renderAutoPagedSortableTable(createEmbeddedResourceTableModel(analysis, index))).join("") +
    `</div>` + renderElfSectionEnd();
};
