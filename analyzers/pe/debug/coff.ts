"use strict";

import { resolveCoffTableReader } from "./coff-addresses.js";
import { readDebugPayload } from "./payload-reader.js";
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

const readCoffSymbolsHeader = async (
  reader: FileRangeReader,
  dataInfo: PeDebugDataLocation, rvaToOff: RvaToOffset,
  addressOfRawDataRva: number, pointerToRawDataOff: number,
  addWarning: (message: string) => void
): Promise<CoffDebugHeader | null> => {
  if (dataInfo.size < COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH) {
    addWarning("COFF debug entry is smaller than IMAGE_COFF_SYMBOLS_HEADER.");
    return null;
  }
  const view = await readDebugPayload(reader, rvaToOff, addressOfRawDataRva,
    pointerToRawDataOff, 0, COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH);
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

const parseDebugLineNumberBlock = async (
  reader: FileRangeReader,
  header: CoffDebugHeader,
  dataSize: number,
  addressOfRawDataRva: number,
  rvaToOff: RvaToOffset,
  pointerToRawDataOff: number,
  addWarning: (message: string) => void
) => {
  const table = resolveCoffTableReader(reader, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, header.lvaToFirstLineNumber,
    header.numberOfLineNumbers * COFF_LINE_NUMBER_RECORD_BYTE_LENGTH);
  if (table == null && header.numberOfLineNumbers) {
    addWarning(`COFF line-number table LVA ${toHex32(header.lvaToFirstLineNumber, 8)} does not map to file data.`);
  }
  return table == null
    ? []
    : [{
        offset: table.toFileOffset(table.offset)!,
        records: await parseCoffLineNumberBlock(
          table.reader,
          table.offset,
          header.numberOfLineNumbers,
          addWarning
        )
      }];
};

const parseDebugTables = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset, dataSize: number,
  header: CoffDebugHeader, addressOfRawDataRva: number, pointerToRawDataOff: number,
  addWarning: (message: string) => void
): Promise<CoffDebugInfo | null> => {
  const table = resolveCoffTableReader(reader, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, header.lvaToFirstSymbol,
    header.numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH);
  if (!table) {
    addWarning(`COFF symbol table LVA ${toHex32(header.lvaToFirstSymbol, 8)} does not map to file data.`);
    return null;
  }
  const { symbols, stringTable } = await parseCoffSymbols(
    table.reader,
    table.offset,
    header.numberOfSymbols,
    addWarning
  );
  return {
    source: "debug-directory",
    header,
    symbolTableOffset: table.toFileOffset(table.offset)!,
    stringTableOffset: stringTable ? table.toFileOffset(stringTable.offset) : null,
    ...(stringTable ? { stringTableSize: stringTable.readableSize } : {}),
    symbols,
    lineNumberBlocks: await parseDebugLineNumberBlock(
      reader,
      header,
      dataSize,
      addressOfRawDataRva,
      rvaToOff,
      pointerToRawDataOff,
      addWarning
    )
  };
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
  const dataInfo = getReadableDebugData("COFF", fileSize, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, dataSize, collectWarning);
  if (!dataInfo) return null;
  const header = await readCoffSymbolsHeader(reader, dataInfo, rvaToOff,
    addressOfRawDataRva, pointerToRawDataOff, collectWarning);
  if (!header) return null;
  const tables = await parseDebugTables(reader, rvaToOff, dataSize, header,
    addressOfRawDataRva, pointerToRawDataOff, collectWarning);
  return tables ? { ...tables, ...(warnings.length ? { warnings } : {}) } : null;
};
