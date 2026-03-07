"use strict";

import { bigFromUint32, clampRangeSize, readRange, readZeroTerminatedString } from "./format.js";
import type { MachOSymbol, MachOSymtabInfo } from "./types.js";

const parseSymtab = async (
  file: File,
  imageOffset: number,
  imageSize: number,
  is64: boolean,
  little: boolean,
  symoff: number,
  nsyms: number,
  stroff: number,
  strsize: number
): Promise<MachOSymtabInfo> => {
  const issues: string[] = [];
  const entrySize = is64 ? 16 : 12;
  const requestedSymbolBytes = nsyms * entrySize;
  const availableSymbolBytes = clampRangeSize(imageSize, symoff, requestedSymbolBytes);
  const symbolCount = Math.floor(availableSymbolBytes / entrySize);
  if (symbolCount < nsyms) {
    issues.push(`Symbol table declares ${nsyms} symbols but only ${symbolCount} entries fit in the image.`);
  }
  const symbolView = await readRange(file, imageOffset + symoff, symbolCount * entrySize);
  const stringSize = clampRangeSize(imageSize, stroff, strsize);
  if (stringSize < strsize) {
    issues.push("String table extends beyond the Mach-O image.");
  }
  const stringBytes = new Uint8Array(
    await file.slice(imageOffset + stroff, imageOffset + stroff + stringSize).arrayBuffer()
  );
  const symbols: MachOSymbol[] = [];
  for (let symbolIndex = 0; symbolIndex < symbolCount; symbolIndex += 1) {
    const offset = symbolIndex * entrySize;
    const stringIndex = symbolView.getUint32(offset, little);
    const type = symbolView.getUint8(offset + 4);
    const sectionIndex = symbolView.getUint8(offset + 5);
    const description = symbolView.getUint16(offset + 6, little);
    const value = is64
      ? symbolView.getBigUint64(offset + 8, little)
      : bigFromUint32(symbolView.getUint32(offset + 8, little));
    if (stringIndex >= stringBytes.length && stringBytes.length > 0) {
      issues.push(`Symbol ${symbolIndex} string index ${stringIndex} is outside the string table.`);
    }
    const libraryOrdinal = (description >>> 8) & 0xff;
    const symbol: MachOSymbol = {
      index: symbolIndex,
      name: stringIndex < stringBytes.length ? readZeroTerminatedString(stringBytes, stringIndex) : "",
      stringIndex,
      type,
      sectionIndex,
      description,
      libraryOrdinal: libraryOrdinal === 0 ? null : libraryOrdinal,
      value
    };
    symbols.push(symbol);
  }
  return {
    symoff,
    nsyms,
    stroff,
    strsize,
    symbols,
    issues
  };
};

export { parseSymtab };
