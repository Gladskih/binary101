"use strict";

import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import type {
  MsvcRttiClassHierarchy,
  MsvcRttiCompleteObjectLocator,
  MsvcRttiVftable
} from "../../analyzers/pe/msvc-rtti/types.js";
import { escapeHtml } from "../../html-utils.js";
import type {
  PagedSortableTableCell,
  PagedSortableTableModel
} from "../paged-sortable-table.js";
import {
  formatMsvcRttiHierarchyAttributes,
  formatMsvcRttiRva,
  formatMsvcRttiVa,
  getMsvcRttiBaseDescriptorCount,
  getMsvcRttiDetailTableModel,
  renderMsvcRttiVftableDetails
} from "./msvc-rtti-details.js";
import { collectPeExactSymbolNames } from "./msvc-rtti-symbols.js";

export const MSVC_RTTI_VFTABLE_TABLE_ID = "pe-msvc-rtti-vftables";

type MsvcRttiTableRow = {
  baseDescriptorCount: number;
  decoratedName: string;
  hierarchy: MsvcRttiClassHierarchy | null;
  locator: MsvcRttiCompleteObjectLocator | null;
  vftable: MsvcRttiVftable;
  vftableIndex: number;
};

const createRows = (pe: PeWindowsParseResult): MsvcRttiTableRow[] => {
  const analysis = pe.msvcRtti;
  if (!analysis) return [];
  const locators = new Map(analysis.completeObjectLocators.map(locator => [locator.rva, locator]));
  const hierarchies = new Map(analysis.classHierarchies.map(hierarchy => [hierarchy.rva, hierarchy]));
  const types = new Map(analysis.types.map(type => [type.rva, type]));
  return analysis.vftables.map((vftable, vftableIndex) => {
    const locator = locators.get(vftable.completeObjectLocatorRva) ?? null;
    return {
      baseDescriptorCount: getMsvcRttiBaseDescriptorCount(pe, vftable),
      decoratedName: types.get(locator?.typeDescriptorRva ?? -1)?.decoratedName ?? "(unresolved)",
      hierarchy: hierarchies.get(locator?.classHierarchyDescriptorRva ?? -1) ?? null,
      locator,
      vftable,
      vftableIndex
    };
  });
};

const numericCell = (value: number): PagedSortableTableCell => ({
  className: "peNumeric",
  html: String(value),
  sortValue: String(value)
});

const rvaCell = (rva: number | null): PagedSortableTableCell => ({
  className: "peNumeric",
  html: rva == null ? `<span class="dim">-</span>` : formatMsvcRttiRva(rva),
  sortValue: rva == null ? "" : String(rva)
});

const vaCell = (imageBase: bigint, rva: number | null): PagedSortableTableCell => ({
  className: "peNumeric",
  html: rva == null ? `<span class="dim">-</span>` : formatMsvcRttiVa(imageBase, rva),
  sortValue: rva == null ? "" : String(rva)
});

const rowCells = (
  imageBase: bigint,
  row: MsvcRttiTableRow
): PagedSortableTableCell[] => {
  const attributes = formatMsvcRttiHierarchyAttributes(row.hierarchy?.attributes ?? 0);
  return [
    {
      html: `<code>${escapeHtml(row.decoratedName)}</code>`,
      sortValue: row.decoratedName
    },
    vaCell(imageBase, row.locator?.rva ?? null),
    rvaCell(row.locator?.rva ?? null),
    numericCell(row.locator?.offset ?? 0),
    numericCell(row.locator?.cdOffset ?? 0),
    vaCell(imageBase, row.vftable.rva),
    rvaCell(row.vftable.rva),
    numericCell(row.vftable.functionTargetRvas.length),
    numericCell(row.baseDescriptorCount),
    { html: escapeHtml(attributes), sortValue: attributes }
  ];
};

const createMainTableModel = (pe: PeWindowsParseResult): PagedSortableTableModel => {
  const rows = createRows(pe);
  const symbolNames = collectPeExactSymbolNames(pe);
  return {
    id: MSVC_RTTI_VFTABLE_TABLE_ID,
    pageSize: 250, // UI page size, not an ABI limit.
    rowCount: rows.length,
    columns: [
      { label: "Decorated type name" },
      { className: "peNumeric", label: "COL VA" },
      { className: "peNumeric", label: "COL RVA" },
      { className: "peNumeric", label: "vfptr offset" },
      { className: "peNumeric", label: "cdOffset" },
      { className: "peNumeric", label: "vftable VA" },
      { className: "peNumeric", label: "vftable RVA" },
      { className: "peNumeric", label: "Slots" },
      { className: "peNumeric", label: "Base descriptors" },
      { label: "Hierarchy attributes" }
    ],
    rowAt: index => {
      const row = rows[index];
      if (!row) return null;
      return {
        additionalRowsHtml: `<tr><td colspan="10">` +
          `${renderMsvcRttiVftableDetails(pe, row.vftableIndex, symbolNames)}</td></tr>`,
        cells: rowCells(pe.opt.ImageBase, row)
      };
    },
    sortValueAt: (rowIndex, columnIndex) => {
      const row = rows[rowIndex];
      return row ? rowCells(pe.opt.ImageBase, row)[columnIndex]?.sortValue ?? "" : "";
    }
  };
};

export const getMsvcRttiPagedTableModel = (
  pe: PeWindowsParseResult,
  tableId: string
): PagedSortableTableModel | null => {
  if (!pe.msvcRtti) return null;
  if (tableId === MSVC_RTTI_VFTABLE_TABLE_ID) return createMainTableModel(pe);
  return getMsvcRttiDetailTableModel(pe, tableId, collectPeExactSymbolNames(pe));
};
