"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { dd, safe } from "../../html-utils.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import { peSectionNameOffset, peSectionNameValue } from "../../analyzers/pe/sections/name.js";

const IMAGE_SYMBOL_SIZE = 18n;

const formatBigByteSize = (value: bigint): string => value <= BigInt(Number.MAX_SAFE_INTEGER)
  ? humanSize(Number(value))
  : `${value} bytes (0x${value.toString(16)})`;

const getCoffSymbolTableSize = (symbolCount: number): bigint =>
  BigInt(symbolCount >>> 0) * IMAGE_SYMBOL_SIZE;

const getCoffStringTableOffset = (pe: PeParseResult): number | null => {
  const pointerToSymbolTable = pe.coff.PointerToSymbolTable >>> 0;
  const numberOfSymbols = pe.coff.NumberOfSymbols >>> 0;
  if (!pointerToSymbolTable || !numberOfSymbols) return null;
  const symbolTableEnd = pointerToSymbolTable + numberOfSymbols * Number(IMAGE_SYMBOL_SIZE);
  return Number.isSafeInteger(symbolTableEnd) ? symbolTableEnd : null;
};

const getRecoveredLongSectionNames = (pe: PeParseResult): Array<{ raw: string; resolved: string }> =>
  (pe.sections || []).flatMap(section => {
    const offset = peSectionNameOffset(section.name);
    const resolved = peSectionNameValue(section.name);
    if (offset == null || resolved === `/${offset}`) return [];
    return [{ raw: `/${offset}`, resolved }];
  });

export const renderCoffTailSummary = (pe: PeParseResult): string | null => {
  if ((pe.coff.NumberOfSymbols >>> 0) === 0 && pe.coffStringTableSize == null) return null;
  const coffSymbolTableSize = getCoffSymbolTableSize(pe.coff.NumberOfSymbols);
  const coffStringTableOffset = getCoffStringTableOffset(pe);
  const recoveredLongSectionNames = getRecoveredLongSectionNames(pe);
  const out = [
    `<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Legacy COFF tail</h4>`,
    `<div class="smallNote">These legacy COFF symbol/string-table structures live outside section data and are not mapped by the PE loader.</div>`,
    `<dl>`,
    dd("SymbolTableOffset", hex(pe.coff.PointerToSymbolTable, 8), "File offset of the legacy COFF symbol table."),
    dd("SymbolRecords", String(pe.coff.NumberOfSymbols >>> 0), "Number of 18-byte COFF symbol records."),
    dd("SymbolTableSize", formatBigByteSize(coffSymbolTableSize), "Total size of the COFF symbol table."),
    dd(
      "StringTableOffset",
      coffStringTableOffset != null ? hex(coffStringTableOffset, 8) : "-",
      "File offset where the COFF string table begins, immediately after the symbol table."
    ),
    dd(
      "StringTableSize",
      pe.coffStringTableSize != null ? humanSize(pe.coffStringTableSize) : "-",
      "Readable bytes of the COFF string table, including the 4-byte size field."
    ),
    dd(
      "RecoveredLongSectionNames",
      String(recoveredLongSectionNames.length),
      "Section names recovered from non-standard /<offset> references into the COFF string table."
    )
  ];
  if (pe.trailingAlignmentPaddingSize) {
    out.push(
      dd(
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
      out.push(`<tr><td>${safe(entry.raw)}</td><td>${safe(entry.resolved)}</td></tr>`);
    }
    out.push(`</tbody></table></details>`);
  }
  out.push(`</section>`);
  return out.join("");
};
