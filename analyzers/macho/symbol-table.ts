"use strict";

import {
  MH_CIGAM,
  MH_CIGAM_64,
  MH_MAGIC,
  MH_MAGIC_64,
  MH_TWOLEVEL,
  N_EXT,
  N_STAB
} from "./commands.js";
import { bigFromUint32, clampRangeSize, createRangeReader } from "./format.js";
import type { MachOFileHeader, MachOSymbol, MachOSymtabInfo } from "./types.js";

type SymbolRecord = {
  stringIndex: number;
  type: number;
  sectionIndex: number;
  description: number;
  value: bigint;
};

type ReadSymbolRecord = (symbolView: DataView, offset: number) => SymbolRecord;

const getTwoLevelLibraryOrdinal = (
  filetype: number,
  headerFlags: number,
  type: number,
  description: number
): number | null => {
  const isDebugSymbol = (type & N_STAB) !== 0;
  const isExternalSymbol = (type & N_EXT) !== 0;
  // mach-o/loader.h: MH_OBJECT == 0x1. Relocatable object files reuse the
  // high byte of n_desc for object-file flags instead of two-level ordinals.
  const isRelocatableObjectFile = filetype === 0x1;
  // mach-o/nlist.h: library ordinals in n_desc are only meaningful for images
  // linked with MH_TWOLEVEL namespace bindings.
  const usesTwoLevelNamespace = (headerFlags & MH_TWOLEVEL) !== 0;
  if (isDebugSymbol || !isExternalSymbol || isRelocatableObjectFile || !usesTwoLevelNamespace) return null;
  return (description >>> 8) & 0xff;
};

const readSymbol32Big = (symbolView: DataView, offset: number): SymbolRecord => ({
  stringIndex: symbolView.getUint32(offset, false),
  type: symbolView.getUint8(offset + 4),
  sectionIndex: symbolView.getUint8(offset + 5),
  description: symbolView.getUint16(offset + 6, false),
  value: bigFromUint32(symbolView.getUint32(offset + 8, false))
});

const readSymbol32Little = (symbolView: DataView, offset: number): SymbolRecord => ({
  stringIndex: symbolView.getUint32(offset, true),
  type: symbolView.getUint8(offset + 4),
  sectionIndex: symbolView.getUint8(offset + 5),
  description: symbolView.getUint16(offset + 6, true),
  value: bigFromUint32(symbolView.getUint32(offset + 8, true))
});

const readSymbol64Big = (symbolView: DataView, offset: number): SymbolRecord => ({
  stringIndex: symbolView.getUint32(offset, false),
  type: symbolView.getUint8(offset + 4),
  sectionIndex: symbolView.getUint8(offset + 5),
  description: symbolView.getUint16(offset + 6, false),
  value: symbolView.getBigUint64(offset + 8, false)
});

const readSymbol64Little = (symbolView: DataView, offset: number): SymbolRecord => ({
  stringIndex: symbolView.getUint32(offset, true),
  type: symbolView.getUint8(offset + 4),
  sectionIndex: symbolView.getUint8(offset + 5),
  description: symbolView.getUint16(offset + 6, true),
  value: symbolView.getBigUint64(offset + 8, true)
});

const getSymbolCount = (
  imageSize: number,
  symoff: number,
  nsyms: number,
  entrySize: number,
  issues: string[]
): number => {
  const availableSymbolBytes = clampRangeSize(imageSize, symoff, nsyms * entrySize);
  const symbolCount = Math.floor(availableSymbolBytes / entrySize);
  if (symbolCount < nsyms) {
    issues.push(`Symbol table declares ${nsyms} symbols but only ${symbolCount} entries fit in the image.`);
  }
  return symbolCount;
};

const getStringTableSize = (
  imageSize: number,
  stroff: number,
  strsize: number,
  issues: string[]
): number => {
  const stringSize = clampRangeSize(imageSize, stroff, strsize);
  if (stringSize < strsize) issues.push("String table extends beyond the Mach-O image.");
  return stringSize;
};

const resolveSymbolName = async (
  stringIndex: number,
  symbolIndex: number,
  stringSize: number,
  stringReader: ReturnType<typeof createRangeReader>,
  nameCache: Map<number, string>,
  issues: string[]
): Promise<string> => {
  if (stringSize === 0 || stringIndex >= stringSize) return "";
  const cachedName = nameCache.get(stringIndex);
  if (cachedName !== undefined) return cachedName;
  const name = await stringReader.readZeroTerminatedString(stringIndex, stringSize - stringIndex);
  if (name.length === stringSize - stringIndex) {
    issues.push(`Symbol ${symbolIndex} name is not NUL-terminated within the string table.`);
  }
  nameCache.set(stringIndex, name);
  return name;
};

const readSymbols = async (
  file: File,
  imageOffset: number,
  symoff: number,
  symbolCount: number,
  entrySize: number,
  readSymbolRecord: ReadSymbolRecord,
  stroff: number,
  stringSize: number,
  filetype: number,
  headerFlags: number,
  issues: string[]
): Promise<MachOSymbol[]> => {
  if (symbolCount === 0) return [];
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
      const symbol = readSymbolRecord(symbolView, batchIndex * entrySize);
      if ((stringSize > 0 && symbol.stringIndex >= stringSize) || (stringSize === 0 && symbol.stringIndex !== 0)) {
        issues.push(`Symbol ${symbolIndex} string index ${symbol.stringIndex} is outside the string table.`);
      }
      symbols.push({
        index: symbolIndex,
        name: await resolveSymbolName(
          symbol.stringIndex,
          symbolIndex,
          stringSize,
          stringReader,
          nameCache,
          issues
        ),
        stringIndex: symbol.stringIndex,
        type: symbol.type,
        sectionIndex: symbol.sectionIndex,
        description: symbol.description,
        libraryOrdinal: getTwoLevelLibraryOrdinal(filetype, headerFlags, symbol.type, symbol.description),
        value: symbol.value
      });
    }
  }
  return symbols;
};

const parseSymbolTable = async (
  file: File,
  imageOffset: number,
  imageSize: number,
  entrySize: number,
  readSymbolRecord: ReadSymbolRecord,
  symoff: number,
  nsyms: number,
  stroff: number,
  strsize: number,
  filetype: number,
  headerFlags: number
): Promise<MachOSymtabInfo> => {
  const issues: string[] = [];
  const symbolCount = getSymbolCount(imageSize, symoff, nsyms, entrySize, issues);
  const stringSize = getStringTableSize(imageSize, stroff, strsize, issues);
  const symbols = await readSymbols(
    file,
    imageOffset,
    symoff,
    symbolCount,
    entrySize,
    readSymbolRecord,
    stroff,
    stringSize,
    filetype,
    headerFlags,
    issues
  );
  return {
    symoff,
    nsyms,
    stroff,
    strsize,
    symbols,
    issues
  };
};

const parseSymtab = async (
  file: File,
  imageOffset: number,
  imageSize: number,
  header: MachOFileHeader,
  symoff: number,
  nsyms: number,
  stroff: number,
  strsize: number
): Promise<MachOSymtabInfo> => {
  switch (header.magic) {
    case MH_MAGIC:
      // mach-o/nlist.h: sizeof(struct nlist) == 12.
      return parseSymbolTable(
        file,
        imageOffset,
        imageSize,
        12,
        readSymbol32Big,
        symoff,
        nsyms,
        stroff,
        strsize,
        header.filetype,
        header.flags
      );
    case MH_CIGAM:
      // mach-o/nlist.h: sizeof(struct nlist) == 12.
      return parseSymbolTable(
        file,
        imageOffset,
        imageSize,
        12,
        readSymbol32Little,
        symoff,
        nsyms,
        stroff,
        strsize,
        header.filetype,
        header.flags
      );
    case MH_MAGIC_64:
      // mach-o/nlist.h: sizeof(struct nlist_64) == 16.
      return parseSymbolTable(
        file,
        imageOffset,
        imageSize,
        16,
        readSymbol64Big,
        symoff,
        nsyms,
        stroff,
        strsize,
        header.filetype,
        header.flags
      );
    case MH_CIGAM_64:
      // mach-o/nlist.h: sizeof(struct nlist_64) == 16.
      return parseSymbolTable(
        file,
        imageOffset,
        imageSize,
        16,
        readSymbol64Little,
        symoff,
        nsyms,
        stroff,
        strsize,
        header.filetype,
        header.flags
      );
    default:
      return {
        symoff,
        nsyms,
        stroff,
        strsize,
        symbols: [],
        issues: [`Symbol table parser does not support Mach-O magic 0x${header.magic.toString(16)}.`]
      };
  }
};

export { parseSymtab };
