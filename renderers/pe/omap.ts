"use strict";

import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { IMAGE_DEBUG_TYPE_OMAP_TO_SRC } from "../../analyzers/pe/debug/types.js";
import { hex } from "../../binary-utils.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";

const createOmapTableModel = (
  entry: PeDebugDirectoryEntry, tableId: string
): PagedSortableTableModel => ({
  id: tableId,
  pageSize: 100,
  rowCount: entry.omap!.records.length,
  columns: [
    { label: "#", className: "peNumeric" },
    { label: entry.type === IMAGE_DEBUG_TYPE_OMAP_TO_SRC
      ? "Image RVA (rva)" : "Source RVA (rva)", className: "peNumeric" },
    { label: entry.type === IMAGE_DEBUG_TYPE_OMAP_TO_SRC
      ? "Source RVA (rvaTo)" : "Image RVA (rvaTo)", className: "peNumeric" }
  ],
  rowAt: index => {
    const record = entry.omap!.records[index];
    return record ? { cells: [
      { html: String(index + 1), className: "peNumeric" },
      { html: hex(record.rva, 8), className: "peNumeric" },
      { html: hex(record.rvaTo, 8), className: "peNumeric" }
    ] } : null;
  },
  sortValueAt: (index, column) => {
    const record = entry.omap!.records[index];
    return record ? String([index + 1, record.rva, record.rvaTo][column] ?? "") : "";
  }
});

export const getOmapTableModel = (
  pe: PeWindowsParseResult, tableId: string
): PagedSortableTableModel | null => {
  const match = /^pe-debug-entry-(\d+)-omap$/.exec(tableId);
  if (!match) return null;
  const entry = pe.debug?.entries?.[Number(match[1])];
  return entry?.omap ? createOmapTableModel(entry, tableId) : null;
};

export const renderOmap = (
  entry: PeDebugDirectoryEntry, entryIndex: number, out: string[]
): void => {
  if (!entry.omap) return;
  // Layout, direction, and interpolation: Microsoft OMAP and PE Debug Type documentation.
  // https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-omap
  // Zero target handling: Wine codeview_map_offset.
  // https://github.com/wine-mirror/wine/blob/master/dlls/dbghelp/msc.c
  out.push(`<p class="smallNote">Source means the original image layout before optimization. ` +
    `Records are shown in file order. In an ordered table, a record applies until the next ` +
    `input RVA; translate by adding the offset from rva to rvaTo. ` +
    `A zero rvaTo indicates an unmapped region. The final region's length is not stored.</p>`);
  if (!entry.omap.records.length) {
    out.push(`<p class="smallNote">No complete OMAP records.</p>`);
    return;
  }
  out.push(renderAutoPagedSortableTable(
    createOmapTableModel(entry, `pe-debug-entry-${entryIndex}-omap`)
  ));
};
