"use strict";

import { toHex32 } from "../../../binary-utils.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { getReadableDebugData, type PeDebugDataLocation } from "./data.js";
import { parseCoffLineNumberBlock } from "../../coff/lines.js";
import { parseCoffSymbols } from "../../coff/symbols.js";
import type { CoffDebugHeader, CoffDebugInfo } from "../../coff/debug-types.js";
import {
  COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH,
  COFF_DEBUG_SYMBOLS_HEADER_FIELDS,
  COFF_LINE_NUMBER_RECORD_BYTE_LENGTH,
  COFF_SYMBOL_RECORD_BYTE_LENGTH,
  readCoffField
} from "../../coff/layout.js";

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
  const fallbackOffset = lva === 0 ? dataInfo.offset + COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH : null;
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
): Promise<CoffDebugHeader | null> => {
  if (dataInfo.size < COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH) {
    addWarning("COFF debug entry is smaller than IMAGE_COFF_SYMBOLS_HEADER.");
    return null;
  }
  const view = await reader.read(dataInfo.offset, COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH);
  if (view.byteLength < COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH) {
    addWarning("COFF debug symbols header is truncated.");
    return null;
  }
  return {
    numberOfSymbols: readCoffField(view, 0, COFF_DEBUG_SYMBOLS_HEADER_FIELDS.NumberOfSymbols),
    lvaToFirstSymbol: readCoffField(view, 0, COFF_DEBUG_SYMBOLS_HEADER_FIELDS.LvaToFirstSymbol),
    numberOfLineNumbers: readCoffField(view, 0, COFF_DEBUG_SYMBOLS_HEADER_FIELDS.NumberOfLineNumbers),
    lvaToFirstLineNumber: readCoffField(view, 0, COFF_DEBUG_SYMBOLS_HEADER_FIELDS.LvaToFirstLineNumber),
    rvaToFirstByteOfCode: readCoffField(view, 0, COFF_DEBUG_SYMBOLS_HEADER_FIELDS.RvaToFirstByteOfCode),
    rvaToLastByteOfCode: readCoffField(view, 0, COFF_DEBUG_SYMBOLS_HEADER_FIELDS.RvaToLastByteOfCode),
    rvaToFirstByteOfData: readCoffField(view, 0, COFF_DEBUG_SYMBOLS_HEADER_FIELDS.RvaToFirstByteOfData),
    rvaToLastByteOfData: readCoffField(view, 0, COFF_DEBUG_SYMBOLS_HEADER_FIELDS.RvaToLastByteOfData)
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
  header: CoffDebugHeader,
  dataInfo: PeDebugDataLocation,
  addressOfRawDataRva: number,
  rvaToOff: RvaToOffset,
  fileSize: number,
  addWarning: (message: string) => void
): number | null => {
  const symbolTableOffset = resolveDebugHeaderTableOffset(
    header.lvaToFirstSymbol,
    header.numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH,
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
  header: CoffDebugHeader,
  dataInfo: PeDebugDataLocation,
  addressOfRawDataRva: number,
  rvaToOff: RvaToOffset,
  fileSize: number,
  addWarning: (message: string) => void
) => {
  const lineNumberOffset = resolveDebugHeaderTableOffset(
    header.lvaToFirstLineNumber,
    header.numberOfLineNumbers * COFF_LINE_NUMBER_RECORD_BYTE_LENGTH,
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
): Promise<CoffDebugInfo | null> => {
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
