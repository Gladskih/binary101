"use strict";

import { toHex32 } from "../../../binary-utils.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeSection, RvaToOffset } from "../types.js";
import { getReadableDebugData, type PeDebugDataLocation } from "./data.js";
import { parseCoffLineNumberBlock, parseSectionCoffLineNumbers } from "./coff-lines.js";
import { parseCoffSymbols } from "./coff-symbols.js";
import {
  IMAGE_COFF_SYMBOLS_HEADER_SIZE,
  IMAGE_LINENUMBER_SIZE,
  IMAGE_SYMBOL_SIZE,
  type PeCoffDebugHeader,
  type PeCoffDebugInfo
} from "./coff-types.js";

export type {
  PeCoffAuxiliaryRecord,
  PeCoffDebugHeader,
  PeCoffDebugInfo,
  PeCoffLineNumber,
  PeCoffLineNumberBlock,
  PeCoffSymbol
} from "./coff-types.js";

const resolveDebugHeaderTableOffset = (
  lva: number,
  minimumBytes: number,
  dataInfo: PeDebugDataLocation,
  addressOfRawDataRva: number,
  rvaToOff: RvaToOffset,
  fileSize: number
): number | null => {
  const payloadEnd = dataInfo.offset + dataInfo.size;
  const payloadCandidates = [
    lva < dataInfo.size ? dataInfo.offset + lva : null,
    addressOfRawDataRva && lva >= addressOfRawDataRva ? dataInfo.offset + (lva - addressOfRawDataRva) : null
  ];
  const validPayloadCandidate = payloadCandidates.find(candidate =>
    candidate != null &&
    candidate >= dataInfo.offset &&
    candidate + Math.min(minimumBytes, 1) <= payloadEnd
  );
  if (validPayloadCandidate != null) return validPayloadCandidate;
  const mappedOffset = lva ? rvaToOff(lva) : null;
  const fallbackOffset = lva === 0 ? dataInfo.offset + IMAGE_COFF_SYMBOLS_HEADER_SIZE : null;
  return [mappedOffset, fallbackOffset].find(candidate =>
    candidate != null &&
    candidate >= 0 &&
    candidate < fileSize &&
    candidate + Math.min(minimumBytes, 1) <= fileSize
  ) ?? null;
};

const readCoffSymbolsHeader = async (
  reader: FileRangeReader,
  dataInfo: PeDebugDataLocation,
  addWarning: (message: string) => void
): Promise<PeCoffDebugHeader | null> => {
  if (dataInfo.size < IMAGE_COFF_SYMBOLS_HEADER_SIZE) {
    addWarning("COFF debug entry is smaller than IMAGE_COFF_SYMBOLS_HEADER.");
    return null;
  }
  const view = await reader.read(dataInfo.offset, IMAGE_COFF_SYMBOLS_HEADER_SIZE);
  if (view.byteLength < IMAGE_COFF_SYMBOLS_HEADER_SIZE) {
    addWarning("COFF debug symbols header is truncated.");
    return null;
  }
  return {
    numberOfSymbols: view.getUint32(0, true),
    lvaToFirstSymbol: view.getUint32(4, true),
    numberOfLineNumbers: view.getUint32(8, true),
    lvaToFirstLineNumber: view.getUint32(12, true),
    rvaToFirstByteOfCode: view.getUint32(16, true),
    rvaToLastByteOfCode: view.getUint32(20, true),
    rvaToFirstByteOfData: view.getUint32(24, true),
    rvaToLastByteOfData: view.getUint32(28, true)
  };
};

const createWarningCollector = (
  warnings: string[],
  addWarning: (message: string) => void
): ((message: string) => void) =>
  message => {
    warnings.push(message);
    addWarning(message);
  };

const resolveDebugSymbolTableOffset = (
  header: PeCoffDebugHeader,
  dataInfo: PeDebugDataLocation,
  addressOfRawDataRva: number,
  rvaToOff: RvaToOffset,
  fileSize: number,
  addWarning: (message: string) => void
): number | null => {
  const symbolTableOffset = resolveDebugHeaderTableOffset(
    header.lvaToFirstSymbol,
    header.numberOfSymbols * IMAGE_SYMBOL_SIZE,
    dataInfo,
    addressOfRawDataRva,
    rvaToOff,
    fileSize
  );
  if (symbolTableOffset == null) {
    addWarning(`COFF symbol table LVA ${toHex32(header.lvaToFirstSymbol, 8)} does not map to file data.`);
  }
  return symbolTableOffset;
};

const parseDebugLineNumberBlock = async (
  reader: FileRangeReader,
  header: PeCoffDebugHeader,
  dataInfo: PeDebugDataLocation,
  addressOfRawDataRva: number,
  rvaToOff: RvaToOffset,
  fileSize: number,
  addWarning: (message: string) => void
) => {
  const lineNumberOffset = resolveDebugHeaderTableOffset(
    header.lvaToFirstLineNumber,
    header.numberOfLineNumbers * IMAGE_LINENUMBER_SIZE,
    dataInfo,
    addressOfRawDataRva,
    rvaToOff,
    fileSize
  );
  if (lineNumberOffset == null && header.numberOfLineNumbers) {
    addWarning(`COFF line-number table LVA ${toHex32(header.lvaToFirstLineNumber, 8)} does not map to file data.`);
  }
  return lineNumberOffset == null
    ? []
    : [{
        offset: lineNumberOffset,
        records: await parseCoffLineNumberBlock(
          reader,
          lineNumberOffset,
          header.numberOfLineNumbers,
          addWarning
        )
      }];
};

export const parseCoffDebugInfo = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  addressOfRawDataRva: number,
  pointerToRawDataOff: number,
  dataSize: number,
  addWarning: (message: string) => void
): Promise<PeCoffDebugInfo | null> => {
  const warnings: string[] = [];
  const collectWarning = createWarningCollector(warnings, addWarning);
  const dataInfo = getReadableDebugData(
    "COFF",
    fileSize,
    rvaToOff,
    addressOfRawDataRva,
    pointerToRawDataOff,
    dataSize,
    collectWarning
  );
  if (!dataInfo) return null;
  const header = await readCoffSymbolsHeader(reader, dataInfo, collectWarning);
  if (!header) return null;
  const symbolTableOffset = resolveDebugSymbolTableOffset(
    header,
    dataInfo,
    addressOfRawDataRva,
    rvaToOff,
    fileSize,
    collectWarning
  );
  if (symbolTableOffset == null) return null;
  const { symbols, stringTable } = await parseCoffSymbols(
    reader,
    symbolTableOffset,
    header.numberOfSymbols,
    collectWarning
  );
  return {
    source: "debug-directory",
    header,
    symbolTableOffset,
    stringTableOffset: stringTable?.offset ?? null,
    ...(stringTable ? { stringTableSize: stringTable.readableSize } : {}),
    symbols,
    lineNumberBlocks: await parseDebugLineNumberBlock(
      reader,
      header,
      dataInfo,
      addressOfRawDataRva,
      rvaToOff,
      fileSize,
      collectWarning
    ),
    ...(warnings.length ? { warnings } : {})
  };
};

export const parseCoffDebugInfoFromFileHeader = async (
  reader: FileRangeReader,
  pointerToSymbolTable: number,
  numberOfSymbols: number,
  sections: PeSection[],
  addWarning: (message: string) => void
): Promise<PeCoffDebugInfo | null> => {
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
