"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { hex, humanSize, isoOrDash } from "../../binary-utils.js";
import type { CoffObjectParseResult } from "../../analyzers/coff/types.js";
import { formatCoffMachine } from "../../analyzers/coff/machine.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import { renderCoffDebugInfo } from "./debug.js";
import { renderCoffRelocations } from "./relocations.js";
import { createCoffSectionTableModel } from "./sections.js";

const renderHeader = (coff: CoffObjectParseResult, out: string[]): void => {
  const header = coff.header;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">COFF file header</h4>`);
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Signature", "COFF"));
  out.push(renderDefinitionRow("Machine", escapeHtml(formatCoffMachine(header.Machine))));
  out.push(renderDefinitionRow("Sections", escapeHtml(String(header.NumberOfSections))));
  out.push(renderDefinitionRow("Timestamp", escapeHtml(isoOrDash(header.TimeDateStamp))));
  out.push(renderDefinitionRow("Symbol table", escapeHtml(hex(header.PointerToSymbolTable, 8))));
  out.push(renderDefinitionRow("Symbols", escapeHtml(String(header.NumberOfSymbols))));
  out.push(renderDefinitionRow("Optional header size", humanSize(header.SizeOfOptionalHeader)));
  out.push(renderDefinitionRow("Characteristics", escapeHtml(hex(header.Characteristics, 4))));
  if (coff.coffStringTableSize != null) {
    out.push(renderDefinitionRow("String table", humanSize(coff.coffStringTableSize)));
  }
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderSections = (coff: CoffObjectParseResult, out: string[]): void => {
  if (!coff.sections.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Section headers</h4>`);
  out.push(renderAutoPagedSortableTable(createCoffSectionTableModel(coff)));
  out.push(`</section>`);
};

const renderDebug = (coff: CoffObjectParseResult, out: string[]): void => {
  if (!coff.coffDebug) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">COFF symbol table</h4>`);
  renderCoffDebugInfo(coff.coffDebug, out, "coff-symbols");
  out.push(`</section>`);
};

const renderWarnings = (coff: CoffObjectParseResult, out: string[]): void => {
  if (!coff.warnings?.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>`);
  out.push(`<ul>`);
  coff.warnings.forEach(warning => out.push(`<li>${escapeHtml(warning)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

export function renderCoff(coff: CoffObjectParseResult | null | undefined): string {
  if (!coff) return "";
  const out: string[] = [];
  renderHeader(coff, out);
  renderSections(coff, out);
  renderCoffRelocations(coff, out);
  renderDebug(coff, out);
  renderWarnings(coff, out);
  return out.join("");
}
