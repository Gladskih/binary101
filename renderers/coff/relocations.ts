"use strict";

import { hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import {
  formatCoffRelocationType
} from "../../analyzers/coff/relocation-types.js";
import type {
  CoffObjectParseResult,
  CoffRelocation,
  CoffRelocationBlock
} from "../../analyzers/coff/types.js";
import {
  renderAutoPagedSortableTable,
  type PagedSortableTableCell,
  type PagedSortableTableModel
} from "../paged-sortable-table.js";

export const COFF_RELOCATION_TABLE_ID_PREFIX = "coff-relocations";
const COFF_RELOCATION_PAGE_SIZE = 250; // UI page size, not a COFF format value.

export const coffRelocationTableId = (sectionIndex: number): string =>
  `${COFF_RELOCATION_TABLE_ID_PREFIX}-${sectionIndex}`;

const createSymbolNameLookup = (coff: CoffObjectParseResult): Map<number, string> =>
  new Map((coff.coffDebug?.symbols ?? []).map(symbol => [symbol.index, symbol.name]));

const relocationSymbolCell = (
  relocation: CoffRelocation,
  symbolNames: Map<number, string>
): PagedSortableTableCell => {
  const symbolName = symbolNames.get(relocation.symbolTableIndex);
  const label = symbolName
    ? `#${relocation.symbolTableIndex} ${symbolName}`
    : `#${relocation.symbolTableIndex}`;
  return { html: escapeHtml(label), sortValue: symbolName ?? String(relocation.symbolTableIndex) };
};

const relocationCells = (
  coff: CoffObjectParseResult,
  block: CoffRelocationBlock,
  relocation: CoffRelocation,
  symbolNames: Map<number, string>
): PagedSortableTableCell[] => [
  { html: String(relocation.index), sortValue: String(relocation.index) },
  { html: escapeHtml(block.sectionName || `#${block.sectionIndex}`), sortValue: block.sectionName },
  { html: hex(relocation.virtualAddress, 8), sortValue: String(relocation.virtualAddress) },
  relocationSymbolCell(relocation, symbolNames),
  relocationTypeCell(coff, relocation)
];

const relocationTypeCell = (
  coff: CoffObjectParseResult,
  relocation: CoffRelocation
): PagedSortableTableCell => {
  const typeName = formatCoffRelocationType(coff.header.Machine, relocation.type);
  return { html: escapeHtml(typeName), sortValue: typeName };
};

export const createCoffRelocationTableModel = (
  coff: CoffObjectParseResult,
  block: CoffRelocationBlock,
  tableId = coffRelocationTableId(block.sectionIndex)
): PagedSortableTableModel => {
  const symbolNames = createSymbolNameLookup(coff);
  return {
    columns: [
      { label: "#" },
      { label: "Section" },
      { label: "Offset" },
      { label: "Symbol" },
      { label: "Type" }
    ],
    id: tableId,
    pageSize: COFF_RELOCATION_PAGE_SIZE,
    rowAt: rowIndex => {
      const relocation = block.records[rowIndex];
      return relocation ? { cells: relocationCells(coff, block, relocation, symbolNames) } : null;
    },
    rowCount: block.records.length,
    sortValueAt: (rowIndex, columnIndex) => {
      const relocation = block.records[rowIndex];
      return relocation
        ? relocationCells(coff, block, relocation, symbolNames)[columnIndex]?.sortValue ?? ""
        : "";
    }
  };
};

export const getCoffRelocationTableModel = (
  coff: CoffObjectParseResult,
  tableId: string
): PagedSortableTableModel | null => {
  if (!tableId.startsWith(`${COFF_RELOCATION_TABLE_ID_PREFIX}-`)) return null;
  const sectionIndex = Number(tableId.slice(COFF_RELOCATION_TABLE_ID_PREFIX.length + 1));
  const block = Number.isSafeInteger(sectionIndex)
    ? coff.relocations?.find(item => item.sectionIndex === sectionIndex)
    : null;
  return block ? createCoffRelocationTableModel(coff, block, tableId) : null;
};

const renderRelocationBlockHeader = (block: CoffRelocationBlock, out: string[]): void => {
  out.push(`<h5 style="margin:.75rem 0 .4rem 0;font-size:.85rem">`);
  out.push(escapeHtml(block.sectionName || `Section #${block.sectionIndex}`));
  out.push(`</h5>`);
  if (block.extendedRelocationCount != null) {
    out.push(`<div class="smallNote">`);
    out.push(`Extended relocation count: ${escapeHtml(String(block.extendedRelocationCount))}`);
    out.push(`</div>`);
  }
};

const renderRelocationBlockWarnings = (block: CoffRelocationBlock, out: string[]): void => {
  if (!block.warnings?.length) return;
  out.push(`<div class="smallNote">${escapeHtml(block.warnings.join(" | "))}</div>`);
};

export const renderCoffRelocations = (coff: CoffObjectParseResult, out: string[]): void => {
  if (!coff.relocations?.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">COFF relocations</h4>`);
  coff.relocations.forEach(block => {
    renderRelocationBlockHeader(block, out);
    if (block.records.length) {
      out.push(renderAutoPagedSortableTable(createCoffRelocationTableModel(coff, block)));
    }
    renderRelocationBlockWarnings(block, out);
  });
  out.push(`</section>`);
};
