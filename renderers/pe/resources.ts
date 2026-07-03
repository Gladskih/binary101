"use strict";

import { humanSize } from "../../binary-utils.js";
import type { PeResources } from "../../analyzers/pe/resources/index.js";
import { escapeHtml } from "../../html-utils.js";
import { renderPeDiagnostics } from "./diagnostics.js";
import { renderPreviewCell, renderPreviewSummary } from "./resource-preview-cell.js";
import { formatWindowsLanguageName } from "./windows-language-names.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import {
  renderAutoPagedSortableTable,
  type PagedSortableTableCell,
  type PagedSortableTableModel
} from "../paged-sortable-table.js";

export const PE_RESOURCE_DETAIL_PAGE_SIZE = 50;

type ResourceDetailGroup = NonNullable<PeResources["detail"]>[number];
type ResourceLangEntry = ResourceDetailGroup["entries"][number]["langs"][number];
type ResourcePreviewRow = {
  displayName: string;
  langEntry: ResourceLangEntry;
};

const formatLang = (lang: number | null | undefined): string => {
  return formatWindowsLanguageName(lang);
};

const formatCodePage = (codePage: number | null | undefined): string =>
  codePage ? String(codePage) : "-";

const formatDirectoryVersion = (majorVersion: number, minorVersion: number): string =>
  majorVersion || minorVersion ? `${majorVersion}.${minorVersion}` : "-";

const formatDirectoryTimestamp = (timeDateStamp: number): string =>
  timeDateStamp ? `0x${timeDateStamp.toString(16).padStart(8, "0")}` : "-";

const formatResourcePathNode = (node: { id: number | null; name: string | null }): string =>
  node.name != null ? escapeHtml(node.name) : node.id != null ? `ID ${node.id}` : "(unnamed)";

const isWideResourcePreview = (
  langEntry: NonNullable<PeResources["detail"]>[number]["entries"][number]["langs"][number]
): boolean =>
  langEntry.previewKind === "dialog" ||
  langEntry.previewKind === "image" ||
  langEntry.previewKind === "stringTable" ||
  langEntry.previewKind === "messageTable" ||
  langEntry.previewKind === "version" ||
  langEntry.previewKind === "menu" ||
  langEntry.previewKind === "accelerator" ||
  langEntry.previewKind === "font" ||
  langEntry.previewKind === "audio" ||
  langEntry.previewKind === "muiConfig" ||
  langEntry.previewKind === "inf" ||
  langEntry.previewKind === "xml" ||
  langEntry.previewKind === "typeLibrary" ||
  langEntry.previewKind === "html" ||
  langEntry.previewKind === "text";

const flattenResourcePreviewRows = (group: ResourceDetailGroup): ResourcePreviewRow[] =>
  group.entries.flatMap(entry => {
    const displayName = entry.name
      ? entry.name
      : entry.id != null
        ? `ID ${entry.id}`
        : "(unnamed)";
    return (entry.langs || []).map(langEntry => ({ displayName, langEntry }));
  });

const resourceTableId = (groupIndex: number): string => `pe-resource-detail-${groupIndex}`;

const renderResourcePreviewCellHtml = (langEntry: ResourceLangEntry): string => {
  if (!isWideResourcePreview(langEntry)) return renderPreviewCell(langEntry);
  return escapeHtml(renderPreviewSummary(langEntry));
};

const renderResourcePreviewAdditionalRowsHtml = (langEntry: ResourceLangEntry): string =>
  isWideResourcePreview(langEntry)
    ? `<tr class="peResourcePreviewWideRow"><td colspan="5">${renderPreviewCell(langEntry)}</td></tr>`
    : "";

const renderResourcePreviewCells = (row: ResourcePreviewRow): PagedSortableTableCell[] => [
  { html: escapeHtml(row.displayName), sortValue: row.displayName },
  {
    html: formatLang(row.langEntry.lang),
    sortValue: formatLang(row.langEntry.lang)
  },
  {
    className: "peNumeric",
    html: humanSize(row.langEntry.size || 0),
    sortValue: String(row.langEntry.size || 0)
  },
  {
    className: "peNumeric",
    html: formatCodePage(row.langEntry.codePage),
    sortValue: String(row.langEntry.codePage || 0)
  },
  {
    html: renderResourcePreviewCellHtml(row.langEntry),
    sortValue: renderPreviewSummary(row.langEntry)
  }
];

const resourcePreviewSortValue = (row: ResourcePreviewRow, columnIndex: number): string => {
  switch (columnIndex) {
    case 0:
      return row.displayName;
    case 1:
      return formatLang(row.langEntry.lang);
    case 2:
      return String(row.langEntry.size || 0);
    case 3:
      return String(row.langEntry.codePage || 0);
    case 4:
      return renderPreviewSummary(row.langEntry);
    default:
      return "";
  }
};

export const createResourceDetailTableModel = (
  group: ResourceDetailGroup,
  groupIndex: number
): PagedSortableTableModel => {
  const rows = flattenResourcePreviewRows(group);
  return {
    columns: [
      { label: "Name / ID" },
      { label: "Lang" },
      { className: "peNumeric", label: "Size" },
      { className: "peNumeric", label: "CodePage" },
      { label: "Preview" }
    ],
    id: resourceTableId(groupIndex),
    pageSize: PE_RESOURCE_DETAIL_PAGE_SIZE,
    rowAt: rowIndex => {
      const row = rows[rowIndex];
      if (!row) return null;
      if (!isWideResourcePreview(row.langEntry)) return { cells: renderResourcePreviewCells(row) };
      return {
        additionalRowsHtml: renderResourcePreviewAdditionalRowsHtml(row.langEntry),
        cells: renderResourcePreviewCells(row),
        className: "peResourcePreviewMetaRow"
      };
    },
    rowCount: rows.length,
    sortValueAt: (rowIndex, columnIndex) =>
      rows[rowIndex] ? resourcePreviewSortValue(rows[rowIndex], columnIndex) : "",
    tableClassName: "peResourcePreviewTable"
  };
};

export const getPeResourceTableModel = (
  resources: PeResources | null | undefined,
  tableId: string
): PagedSortableTableModel | null => {
  const match = tableId.match(/^pe-resource-detail-(\d+)$/);
  if (!match?.[1]) return null;
  const groupIndex = Number(match[1]);
  const group = resources?.detail?.[groupIndex];
  return group && Number.isInteger(groupIndex)
    ? createResourceDetailTableModel(group, groupIndex)
    : null;
};

const renderResourceIntro = (resources: PeResources, out: string[]): void => {
  const topRows = resources.top || [];
  out.push(
    renderPeSectionStart(
      "Resources",
      `${topRows.length} kind${topRows.length === 1 ? "" : "s"}`
    )
  );
  out.push(
    `<div class="smallNote">Windows resources usually follow a three-level tree: ` +
      `type → name/ID → language. Canonical .rsrc layout is directory entries → ` +
      `directory strings → data entries. This view previews common standard ` +
      `resources such as icons, cursors, bitmaps, dialogs, menus, accelerators, ` +
      `message tables, version info, and heuristic payloads carried by RCDATA or ` +
      `custom types.</div>`
  );
  if (resources.issues?.length) {
    out.push(renderPeDiagnostics("Resource warnings", resources.issues.filter(Boolean)));
  }
};

const renderTopResourceKinds = (resources: PeResources, out: string[]): void => {
  const topRows = resources.top || [];
  if (!topRows.length) return;
  if (topRows.length > 12) {
    out.push(
      `<details style="margin-top:.75rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>Top-level resource kinds</b> - ${topRows.length} type bucket${topRows.length === 1 ? "" : "s"}</summary>`
    );
  }
  out.push(
    `<table class="table" style="margin-top:.5rem"><thead><tr><th>Type</th><th>Key kind</th><th>Leaf entries</th></tr></thead><tbody>`
  );
  for (const row of topRows) {
    const typeName = escapeHtml(row.typeName || "(unknown)");
    const kind = row.kind === "name" ? "string name" : "numeric ID";
    out.push(`<tr><td>${typeName}</td><td>${kind}</td><td>${row.leafCount ?? 0}</td></tr>`);
  }
  out.push(`</tbody></table>`);
  if (topRows.length > 12) out.push(`</details>`);
};

const renderResourceDirectories = (resources: PeResources, out: string[]): void => {
  if (!resources.directories?.length) return;
  out.push(
    `<details style="margin-top:.75rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>IMAGE_RESOURCE_DIRECTORY</b> - ${resources.directories.length} table${resources.directories.length === 1 ? "" : "s"}</summary>`
  );
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>Offset</th><th>Timestamp</th><th>Version</th><th>Named</th><th>ID</th></tr></thead><tbody>`
  );
  for (const directory of resources.directories) {
    out.push(
      `<tr><td class="mono">0x${directory.offset.toString(16)}</td><td class="mono">${formatDirectoryTimestamp(directory.timeDateStamp)}</td><td>${formatDirectoryVersion(directory.majorVersion, directory.minorVersion)}</td><td>${directory.namedEntries}</td><td>${directory.idEntries}</td></tr>`
    );
  }
  out.push(`</tbody></table></details>`);
};

const renderResourceDetails = (resources: PeResources, out: string[]): void => {
  if (!resources.detail?.length) return;
  resources.detail.forEach((group, groupIndex) => {
    const typeName = escapeHtml(group.typeName || "(unknown)");
    const entryCount = flattenResourcePreviewRows(group).length;
    out.push(
      `<details style="margin-top:.75rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${typeName}</b> - ${entryCount} entr${entryCount === 1 ? "y" : "ies"}</summary>`
    );
    if (entryCount) {
      out.push(renderAutoPagedSortableTable(createResourceDetailTableModel(group, groupIndex)));
    }
    out.push(`</details>`);
  });
};

const renderAdditionalResourcePaths = (resources: PeResources, out: string[]): void => {
  const extraPaths = (resources.paths || []).filter(path => path.nodes.length !== 3);
  if (!extraPaths.length) return;
  out.push(
    `<details style="margin-top:.75rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>Additional resource paths</b> - ${extraPaths.length}</summary>`
  );
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>Path</th><th>Size</th><th>CodePage</th><th>Data RVA</th></tr></thead><tbody>`
  );
  for (const path of extraPaths) {
    out.push(
      `<tr><td>${path.nodes.map(formatResourcePathNode).join(" / ")}</td><td>${humanSize(path.size)}</td><td>${formatCodePage(path.codePage)}</td><td class="mono">0x${path.dataRVA.toString(16)}</td></tr>`
    );
  }
  out.push(`</tbody></table></details>`);
};

export function renderResources(resources: PeResources, out: string[]): void {
  renderResourceIntro(resources, out);
  renderTopResourceKinds(resources, out);
  renderResourceDirectories(resources, out);
  renderResourceDetails(resources, out);
  renderAdditionalResourcePaths(resources, out);
  out.push(renderPeSectionEnd());
}
