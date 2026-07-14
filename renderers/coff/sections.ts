"use strict";

import { escapeHtml } from "../../html-utils.js";
import { hex, humanSize } from "../../binary-utils.js";
import {
  coffSectionNameOffset,
  coffSectionNameValue
} from "../../analyzers/coff/section-name.js";
import type { CoffObjectParseResult, CoffSection } from "../../analyzers/coff/types.js";
import type {
  PagedSortableTableCell,
  PagedSortableTableModel
} from "../paged-sortable-table.js";
import {
  SECTION_ENTROPY_TOOLTIP,
  renderSectionEntropyValue,
  sectionEntropySortValue
} from "../section-entropy.js";

export const COFF_SECTION_TABLE_ID = "coff-sections";
const COFF_SECTION_PAGE_SIZE = 200; // UI page size, not a COFF format value.

const sectionNameCell = (section: CoffSection): PagedSortableTableCell => {
  const name = coffSectionNameValue(section.name);
  const offset = coffSectionNameOffset(section.name);
  const baseName = escapeHtml(name || "(unnamed)");
  return {
    html: offset != null && name !== `/${offset}`
      ? `${baseName}<div class="smallNote dim">COFF name /${offset}</div>`
      : baseName,
    sortValue: name
  };
};

const sectionCells = (section: CoffSection, sectionIndex: number): PagedSortableTableCell[] => [
  sectionNameCell(section),
  { html: humanSize(section.virtualSize), sortValue: String(section.virtualSize) },
  { html: hex(section.virtualAddress, 8), sortValue: String(section.virtualAddress) },
  { html: humanSize(section.sizeOfRawData), sortValue: String(section.sizeOfRawData) },
  { html: hex(section.pointerToRawData, 8), sortValue: String(section.pointerToRawData) },
  { html: hex(section.pointerToRelocations ?? 0, 8), sortValue: String(section.pointerToRelocations ?? 0) },
  { html: String(section.numberOfRelocations ?? 0), sortValue: String(section.numberOfRelocations ?? 0) },
  { html: hex(section.pointerToLinenumbers ?? 0, 8), sortValue: String(section.pointerToLinenumbers ?? 0) },
  { html: String(section.numberOfLinenumbers ?? 0), sortValue: String(section.numberOfLinenumbers ?? 0) },
  {
    className: "sectionEntropy__value",
    html: renderSectionEntropyValue(section.entropy, sectionIndex),
    sortValue: sectionEntropySortValue(section.entropy)
  },
  { html: hex(section.characteristics, 8), sortValue: String(section.characteristics >>> 0) }
];

export const createCoffSectionTableModel = (
  coff: CoffObjectParseResult,
  tableId = COFF_SECTION_TABLE_ID
): PagedSortableTableModel => ({
  columns: [
    { label: "Name" },
    { label: "VirtualSize" },
    { label: "VirtualAddr" },
    { label: "RawSize" },
    { label: "RawPtr" },
    { label: "RelocPtr" },
    { label: "Relocs" },
    { label: "LinePtr" },
    { label: "Lines" },
    {
      className: "sectionEntropy__value",
      label: "Entropy",
      tooltip: SECTION_ENTROPY_TOOLTIP
    },
    { label: "Flags" }
  ],
  id: tableId,
  pageSize: COFF_SECTION_PAGE_SIZE,
  rowAt: rowIndex => {
    const section = coff.sections[rowIndex];
    return section ? { cells: sectionCells(section, rowIndex) } : null;
  },
  rowCount: coff.sections.length,
  sortValueAt: (rowIndex, columnIndex) => {
    const section = coff.sections[rowIndex];
    return section ? sectionCells(section, rowIndex)[columnIndex]?.sortValue ?? "" : "";
  }
});
