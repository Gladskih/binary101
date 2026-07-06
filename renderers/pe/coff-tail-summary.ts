"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import { peSectionNameOffset, peSectionNameValue } from "../../analyzers/pe/sections/name.js";
import { COFF_SYMBOL_RECORD_BYTE_LENGTH } from "../../analyzers/coff/layout.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import {
  getCoffAuxiliaryRecordCount,
  getCoffParsedRecordCount,
  renderCoffDebugTables
} from "../coff/debug.js";

const COFF_SYMBOL_RECORD_BYTE_LENGTH_BIGINT = BigInt(COFF_SYMBOL_RECORD_BYTE_LENGTH);

const formatBigByteSize = (value: bigint): string => value <= BigInt(Number.MAX_SAFE_INTEGER)
  ? humanSize(Number(value))
  : `${value} bytes (0x${value.toString(16)})`;

const getCoffSymbolTableSize = (symbolCount: number): bigint =>
  BigInt(symbolCount >>> 0) * COFF_SYMBOL_RECORD_BYTE_LENGTH_BIGINT;

const getCoffStringTableOffset = (pe: PeParseResult): number | null => {
  const pointerToSymbolTable = pe.coff.PointerToSymbolTable >>> 0;
  const numberOfSymbols = pe.coff.NumberOfSymbols >>> 0;
  if (!pointerToSymbolTable || !numberOfSymbols) return null;
  const symbolTableEnd = pointerToSymbolTable + numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  return Number.isSafeInteger(symbolTableEnd) ? symbolTableEnd : null;
};

const getRecoveredLongSectionNames = (pe: PeParseResult): Array<{ raw: string; resolved: string }> =>
  (pe.sections || []).flatMap(section => {
    const offset = peSectionNameOffset(section.name);
    const resolved = peSectionNameValue(section.name);
    if (offset == null || resolved === `/${offset}`) return [];
    return [{ raw: `/${offset}`, resolved }];
  });

const getFileHeaderCoffDebug = (pe: PeParseResult) =>
  pe.coffDebug?.source === "coff-header" ? pe.coffDebug : null;

const legacyCoffTailSummary = (recordCount: number): string =>
  recordCount === 1 ? "1 symbol-table record" : `${recordCount} symbol-table records`;

const renderInlineSubheading = (title: string): string =>
  `<h4 style="margin:.75rem 0 .5rem 0;font-size:.9rem">${escapeHtml(title)}</h4>`;

const renderParsedCoffDebugInfo = (pe: PeParseResult, out: string[]): void => {
  const coffDebug = getFileHeaderCoffDebug(pe);
  if (!coffDebug) return;
  out.push(renderInlineSubheading("Parsed COFF symbol table"));
  out.push(
    `<div class="smallNote">NumberOfSymbols counts symbol-table records, including ` +
      `auxiliary records. The table below groups auxiliary records under their owning ` +
      `primary symbol, so the visible symbol row count can be lower.</div>`
  );
  renderCoffDebugTables(coffDebug, out, "pe-coff-symbols");
};

const renderParsedCoffDebugRows = (pe: PeParseResult): string[] => {
  const coffDebug = getFileHeaderCoffDebug(pe);
  if (!coffDebug) return [];
  return [
    renderDefinitionRow(
      "PrimarySymbolsParsed",
      String(coffDebug.symbols.length),
      "Standard symbol records parsed from the COFF symbol table."
    ),
    renderDefinitionRow(
      "AuxiliaryRecordsParsed",
      String(getCoffAuxiliaryRecordCount(coffDebug)),
      "Auxiliary symbol records grouped under primary symbols."
    ),
    renderDefinitionRow(
      "SymbolRecordsParsed",
      String(getCoffParsedRecordCount(coffDebug)),
      "Primary plus auxiliary symbol records parsed from the table."
    )
  ];
};

export const renderCoffTailSummary = (pe: PeParseResult): string | null => {
  if ((pe.coff.NumberOfSymbols >>> 0) === 0 && pe.coffStringTableSize == null) return null;
  const coffSymbolTableSize = getCoffSymbolTableSize(pe.coff.NumberOfSymbols);
  const coffStringTableOffset = getCoffStringTableOffset(pe);
  const recoveredLongSectionNames = getRecoveredLongSectionNames(pe);
  const symbolRecordCount = pe.coff.NumberOfSymbols >>> 0;
  const out = [
    renderPeSectionStart(
      "Legacy COFF tail",
      legacyCoffTailSummary(symbolRecordCount)
    ),
    `<div class="smallNote">These deprecated COFF symbol/string-table structures are ` +
      `referenced by the COFF file header, live outside mapped section data, and are ` +
      `not mapped by the PE loader.</div>`,
    `<dl>`,
    renderDefinitionRow("SymbolTableOffset", hex(pe.coff.PointerToSymbolTable, 8), "File offset of the legacy COFF symbol table."),
    renderDefinitionRow(
      "SymbolTableRecords",
      String(symbolRecordCount),
      "COFF header NumberOfSymbols: 18-byte symbol-table records, including auxiliary records."
    ),
    renderDefinitionRow("SymbolTableSize", formatBigByteSize(coffSymbolTableSize), "Total size of the COFF symbol table."),
    renderDefinitionRow(
      "StringTableOffset",
      coffStringTableOffset != null ? hex(coffStringTableOffset, 8) : "-",
      "File offset where the COFF string table begins, immediately after the symbol table."
    ),
    renderDefinitionRow(
      "StringTableSize",
      pe.coffStringTableSize != null ? humanSize(pe.coffStringTableSize) : "-",
      "Readable bytes of the COFF string table, including the 4-byte size field."
    ),
    renderDefinitionRow(
      "RecoveredLongSectionNames",
      String(recoveredLongSectionNames.length),
      "Section names recovered from non-standard /<offset> references into the COFF string table."
    )
  ];
  out.push(...renderParsedCoffDebugRows(pe));
  if (pe.trailingAlignmentPaddingSize) {
    out.push(
      renderDefinitionRow(
        "TrailingAlignmentPadding",
        humanSize(pe.trailingAlignmentPaddingSize),
        "Zero-filled bytes that only pad the file tail to FileAlignment."
      )
    );
  }
  out.push(`</dl>`);
  if (recoveredLongSectionNames.length) {
    out.push(
      `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Recovered long section names (${recoveredLongSectionNames.length})</summary>`
    );
    out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>Raw</th><th>Resolved</th></tr></thead><tbody>`);
    for (const entry of recoveredLongSectionNames) {
      out.push(`<tr><td>${escapeHtml(entry.raw)}</td><td>${escapeHtml(entry.resolved)}</td></tr>`);
    }
    out.push(`</tbody></table></details>`);
  }
  renderParsedCoffDebugInfo(pe, out);
  out.push(renderPeSectionEnd());
  return out.join("");
};
