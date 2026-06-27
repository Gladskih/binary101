"use strict";

import { escapeHtml } from "../../html-utils.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { peSectionNameValue } from "../../analyzers/pe/sections/name.js";
import type {
  PeApiStringReference,
  PeCodeStringReference
} from "../../analyzers/pe/disassembly/index.js";
import {
  renderPagedSortableTable,
  type PagedSortableTableModel,
  type PagedSortableTableRow
} from "../paged-sortable-table.js";

export const PE_CODE_STRING_TABLE_ID = "peCodeStringReferences";
export const PE_API_STRING_TABLE_ID = "peApiStringReferences";
export const PE_DISASSEMBLY_STRING_INLINE_LIMIT = 1000;
export const PE_DISASSEMBLY_STRING_PAGE_SIZE = 500;

type StringReferenceCellValues = [string, string, string, string, string, string];

const formatRva = (rva: number): string => `0x${(rva >>> 0).toString(16).padStart(8, "0")}`;

const clippedText = (text: string): string =>
  text.length > 120 ? `${text.slice(0, 117)}...` : text;

const sourceLabel = (sourceKind: PeApiStringReference["callSites"][number]["sourceKind"]): string =>
  sourceKind === "ucrt" ? "UCRT" : "WinAPI";

const sectionForRva = (pe: PeWindowsParseResult, rva: number): string => {
  const section = pe.sections.find(candidate => {
    const start = candidate.virtualAddress >>> 0;
    const span = (candidate.virtualSize >>> 0) || (candidate.sizeOfRawData >>> 0);
    return rva >= start && rva < start + span;
  });
  return section ? peSectionNameValue(section.name) || "(unnamed)" : "-";
};

const renderCodeStringInstructionRvas = (reference: PeCodeStringReference): string => {
  const rvas = reference.instructionRvas.slice(0, 5).map(formatRva);
  const suffix = reference.instructionRvas.length > rvas.length
    ? ` +${reference.instructionRvas.length - rvas.length} more`
    : "";
  return escapeHtml(`${rvas.join(", ")}${suffix}`);
};

const codeStringCellValues = (
  pe: PeWindowsParseResult,
  reference: PeCodeStringReference
): StringReferenceCellValues => [
  formatRva(reference.rva),
  sectionForRva(pe, reference.rva),
  reference.encoding,
  String(reference.instructionRvas.length),
  reference.instructionRvas.map(formatRva).join(", "),
  reference.text
];

const renderCodeStringRow = (
  pe: PeWindowsParseResult,
  reference: PeCodeStringReference
): string => {
  return `<tr>${renderCodeStringCells(pe, reference).map(cell =>
    `<td${cell.className ? ` class="${cell.className}"` : ""}>${cell.html}</td>`
  ).join("")}</tr>`;
};

const renderCodeStringCells = (
  pe: PeWindowsParseResult,
  reference: PeCodeStringReference
): PagedSortableTableRow["cells"] => {
  const values = codeStringCellValues(pe, reference);
  return [
    { html: escapeHtml(values[0]), sortValue: String(reference.rva), className: "peNumeric" },
    { html: escapeHtml(values[1]), sortValue: values[1] },
    { html: escapeHtml(values[2]), sortValue: values[2] },
    {
      html: escapeHtml(values[3]),
      sortValue: values[3],
      className: "peNumeric"
    },
    { html: renderCodeStringInstructionRvas(reference), sortValue: values[4] },
    {
      html: `<code title="${escapeHtml(reference.text)}">${escapeHtml(clippedText(reference.text))}</code>`,
      sortValue: values[5]
    }
  ];
};

const renderApiStringCallSites = (reference: PeApiStringReference): string => {
  const sites = reference.callSites.slice(0, 3).map(site => {
    const parameter = site.parameterName ?? `arg${site.parameterIndex + 1}`;
    return `${sourceLabel(site.sourceKind)} ${site.module}!${site.entrypoint} ` +
      `${parameter} @ ${formatRva(site.instructionRva)}`;
  });
  const suffix = reference.callSites.length > sites.length
    ? ` +${reference.callSites.length - sites.length} more`
    : "";
  return escapeHtml(`${sites.join("; ")}${suffix}`);
};

const apiStringCellValues = (
  pe: PeWindowsParseResult,
  reference: PeApiStringReference
): StringReferenceCellValues => [
  formatRva(reference.rva),
  sectionForRva(pe, reference.rva),
  reference.encoding,
  String(reference.callSites.length),
  reference.callSites.map(site =>
    `${sourceLabel(site.sourceKind)} ${site.module}!${site.entrypoint}`
  ).join("; "),
  reference.text
];

const renderApiStringRow = (
  pe: PeWindowsParseResult,
  reference: PeApiStringReference
): string =>
  `<tr>${renderApiStringCells(pe, reference).map(cell =>
    `<td${cell.className ? ` class="${cell.className}"` : ""}>${cell.html}</td>`
  ).join("")}</tr>`;

const renderApiStringCells = (
  pe: PeWindowsParseResult,
  reference: PeApiStringReference
): PagedSortableTableRow["cells"] => {
  const values = apiStringCellValues(pe, reference);
  return [
    { html: escapeHtml(values[0]), sortValue: String(reference.rva), className: "peNumeric" },
    { html: escapeHtml(values[1]), sortValue: values[1] },
    { html: escapeHtml(values[2]), sortValue: values[2] },
    { html: escapeHtml(values[3]), sortValue: values[3], className: "peNumeric" },
    { html: renderApiStringCallSites(reference), sortValue: values[4] },
    {
      html: `<code title="${escapeHtml(reference.text)}">${escapeHtml(clippedText(reference.text))}</code>`,
      sortValue: values[5]
    }
  ];
};

export const createPeCodeStringTableModel = (
  pe: PeWindowsParseResult
): PagedSortableTableModel | null => {
  const references = pe.disassembly?.codeStringReferences ?? [];
  if (!references.length) return null;
  return {
    id: PE_CODE_STRING_TABLE_ID,
    rowCount: references.length,
    pageSize: PE_DISASSEMBLY_STRING_PAGE_SIZE,
    columns: [
      { label: "RVA", className: "peNumeric" },
      { label: "Section" },
      { label: "Encoding" },
      { label: "Refs", className: "peNumeric" },
      { label: "Code refs" },
      { label: "Text" }
    ],
    rowAt: rowIndex => {
      const reference = references[rowIndex];
      return reference ? { cells: renderCodeStringCells(pe, reference) } : null;
    },
    sortValueAt: (rowIndex, columnIndex) => {
      const reference = references[rowIndex];
      return reference ? codeStringCellValues(pe, reference)[columnIndex] ?? "" : "";
    }
  };
};

export const createPeApiStringTableModel = (
  pe: PeWindowsParseResult
): PagedSortableTableModel | null => {
  const references = pe.disassembly?.apiStringReferences ?? [];
  if (!references.length) return null;
  return {
    id: PE_API_STRING_TABLE_ID,
    rowCount: references.length,
    pageSize: PE_DISASSEMBLY_STRING_PAGE_SIZE,
    columns: [
      { label: "RVA", className: "peNumeric" },
      { label: "Section" },
      { label: "Encoding" },
      { label: "Refs", className: "peNumeric" },
      { label: "API argument" },
      { label: "Text" }
    ],
    rowAt: rowIndex => {
      const reference = references[rowIndex];
      return reference ? { cells: renderApiStringCells(pe, reference) } : null;
    },
    sortValueAt: (rowIndex, columnIndex) => {
      const reference = references[rowIndex];
      return reference ? apiStringCellValues(pe, reference)[columnIndex] ?? "" : "";
    }
  };
};

export const getPeDisassemblyStringTableModel = (
  pe: PeWindowsParseResult,
  tableId: string
): PagedSortableTableModel | null => {
  if (tableId === PE_CODE_STRING_TABLE_ID) return createPeCodeStringTableModel(pe);
  if (tableId === PE_API_STRING_TABLE_ID) return createPeApiStringTableModel(pe);
  return null;
};

export const renderCodeStringReferences = (pe: PeWindowsParseResult, out: string[]): void => {
  const references = pe.disassembly?.codeStringReferences ?? [];
  if (!references.length) {
    out.push(`<div class="smallNote dim">No code-referenced strings were detected.</div>`);
    return;
  }
  const model = createPeCodeStringTableModel(pe);
  renderStringReferenceDetails(
    out,
    `Code-referenced strings (${references.length})`,
    references.length > PE_DISASSEMBLY_STRING_INLINE_LIMIT && model
      ? renderPagedSortableTable(model)
      : renderCodeStringTable(pe, references)
  );
};

export const renderApiStringReferences = (pe: PeWindowsParseResult, out: string[]): void => {
  const references = pe.disassembly?.apiStringReferences ?? [];
  if (!references.length) {
    out.push(
      `<div class="smallNote dim">No WinAPI/UCRT string arguments were detected ` +
      `in direct imported calls.</div>`
    );
    return;
  }
  const model = createPeApiStringTableModel(pe);
  renderStringReferenceDetails(
    out,
    `WinAPI/UCRT string arguments (${references.length})`,
    references.length > PE_DISASSEMBLY_STRING_INLINE_LIMIT && model
      ? renderPagedSortableTable(model)
      : renderApiStringTable(pe, references)
  );
};

const renderStringReferenceDetails = (
  out: string[],
  summary: string,
  body: string
): void => {
  out.push(
    `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">` +
    `${escapeHtml(summary)}</summary>${body}</details>`
  );
};

const renderCodeStringTable = (
  pe: PeWindowsParseResult,
  references: readonly PeCodeStringReference[]
): string =>
  `<div class="tableWrap"><table class="table" style="margin-top:.35rem">` +
  `<thead><tr><th class="peNumeric">RVA</th><th>Section</th><th>Encoding</th>` +
  `<th class="peNumeric">Refs</th><th>Code refs</th><th>Text</th></tr></thead>` +
  `<tbody>${references.map(reference => renderCodeStringRow(pe, reference)).join("")}` +
  `</tbody></table></div>`;

const renderApiStringTable = (
  pe: PeWindowsParseResult,
  references: readonly PeApiStringReference[]
): string =>
  `<div class="tableWrap"><table class="table" style="margin-top:.35rem">` +
  `<thead><tr><th class="peNumeric">RVA</th><th>Section</th><th>Encoding</th>` +
  `<th class="peNumeric">Refs</th><th>API argument</th><th>Text</th></tr></thead>` +
  `<tbody>${references.map(reference => renderApiStringRow(pe, reference)).join("")}` +
  `</tbody></table></div>`;
