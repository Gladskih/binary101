"use strict";

import { bigFromUint32, clampRangeSize, createRangeReader } from "./format.js";
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
  const stringSize = clampRangeSize(imageSize, stroff, strsize);
  if (stringSize < strsize) {
    issues.push("String table extends beyond the Mach-O image.");
  }
  const symbolReader = createRangeReader(file, imageOffset + symoff, symbolCount * entrySize);
  const stringReader = createRangeReader(file, imageOffset + stroff, stringSize);
  const nameCache = new Map<number, string>();
  const symbolsPerBatch = Math.max(1, Math.floor((64 * 1024) / entrySize));
  const symbols: MachOSymbol[] = [];
  for (let batchStart = 0; batchStart < symbolCount; batchStart += symbolsPerBatch) {
    const batchCount = Math.min(symbolsPerBatch, symbolCount - batchStart);
    const symbolView = await symbolReader.read(batchStart * entrySize, batchCount * entrySize);
    for (let batchIndex = 0; batchIndex < batchCount; batchIndex += 1) {
      const symbolIndex = batchStart + batchIndex;
      const offset = batchIndex * entrySize;
      const stringIndex = symbolView.getUint32(offset, little);
      const type = symbolView.getUint8(offset + 4);
      const sectionIndex = symbolView.getUint8(offset + 5);
      const description = symbolView.getUint16(offset + 6, little);
      const value = is64
        ? symbolView.getBigUint64(offset + 8, little)
        : bigFromUint32(symbolView.getUint32(offset + 8, little));
      if (stringIndex >= stringSize && stringSize > 0) {
        issues.push(`Symbol ${symbolIndex} string index ${stringIndex} is outside the string table.`);
      }
      let name = "";
      if (stringIndex < stringSize) {
        name = nameCache.get(stringIndex) || "";
        if (!nameCache.has(stringIndex)) {
          name = await stringReader.readZeroTerminatedString(stringIndex, stringSize - stringIndex);
          nameCache.set(stringIndex, name);
        }
      }
      const libraryOrdinal = (description >>> 8) & 0xff;
      symbols.push({
        index: symbolIndex,
        name,
        stringIndex,
        type,
        sectionIndex,
        description,
        libraryOrdinal: libraryOrdinal === 0 ? null : libraryOrdinal,
        value
      });
    }
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
