"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { CoffSection } from "./types.js";
import { parseCoffSymbols } from "./symbols.js";
import { parseSectionCoffLineNumbers } from "./lines.js";
import type { CoffDebugInfo } from "./debug-types.js";

const createWarningCollector = (
  warnings: string[],
  addWarning: (message: string) => void
): ((message: string) => void) =>
  message => {
    warnings.push(message);
    addWarning(message);
  };

export const parseCoffDebugInfoFromFileHeader = async (
  reader: FileRangeReader,
  pointerToSymbolTable: number,
  numberOfSymbols: number,
  sections: CoffSection[],
  addWarning: (message: string) => void
): Promise<CoffDebugInfo | null> => {
  if (!pointerToSymbolTable || !numberOfSymbols) return null;
  const warnings: string[] = [];
  const collectWarning = createWarningCollector(warnings, addWarning);
  if (pointerToSymbolTable >= reader.size) {
    collectWarning("COFF symbol table starts past end of file.");
    return {
      source: "coff-header",
      symbolTableOffset: pointerToSymbolTable,
      stringTableOffset: null,
      symbols: [],
      lineNumberBlocks: [],
      warnings
    };
  }
  const { symbols, stringTable } = await parseCoffSymbols(
    reader,
    pointerToSymbolTable,
    numberOfSymbols,
    collectWarning
  );
  return {
    source: "coff-header",
    symbolTableOffset: pointerToSymbolTable,
    stringTableOffset: stringTable?.offset ?? null,
    ...(stringTable ? { stringTableSize: stringTable.readableSize } : {}),
    symbols,
    lineNumberBlocks: await parseSectionCoffLineNumbers(reader, sections, collectWarning),
    ...(warnings.length ? { warnings } : {})
  };
};
