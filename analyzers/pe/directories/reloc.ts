"use strict";

import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";

const IMAGE_REL_BASED_RESERVED = 6;
const IMAGE_REL_BASED_HIGHADJ = 4;
export const IMAGE_REL_BASED_DIR64 = 10;
const BASE_RELOCATION_PAGE_SIZE = 0x1000;
// Microsoft PE/COFF: IMAGE_BASE_RELOCATION consists of an 8-byte header followed by WORD entries.
const IMAGE_BASE_RELOCATION_HEADER_SIZE = 8;
const IMAGE_BASE_RELOCATION_ENTRY_SIZE = Uint16Array.BYTES_PER_ELEMENT;

export interface PeBaseRelocationEntry {
  type: number;
  offset: number;
}

export interface PeBaseRelocationBlock {
  pageRva: number;
  size: number;
  count: number;
  entries: PeBaseRelocationEntry[];
}

export interface PeBaseRelocationResult {
  blocks: PeBaseRelocationBlock[];
  totalEntries: number;
  warnings?: string[];
}

const parseRelocationEntries = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset, rva: number, wordCount: number,
  addWarning: (message: string) => void
): Promise<PeBaseRelocationEntry[]> => {
  const entries: PeBaseRelocationEntry[] = [];
  let skipPayload = false;
  for (let index = 0; index < wordCount;) {
    // Bound temporary memory to the shared reader's 64 KiB window.
    const requestedWords = Math.min(wordCount - index, 32768);
    const view = await readMappedRvaPrefix(reader, rva + index * 2, requestedWords * 2, rvaToOff);
    for (let offset = 0; offset + 2 <= view.byteLength; offset += 2) {
      if (skipPayload) { skipPayload = false; continue; }
      const raw = view.getUint16(offset, true);
      const type = raw >>> 12;
      if (type === IMAGE_REL_BASED_RESERVED) addWarning("Base relocation entry uses reserved type 6.");
      entries.push({ type, offset: raw & 0xfff });
      skipPayload = type === IMAGE_REL_BASED_HIGHADJ;
    }
    if (view.byteLength < requestedWords * 2) {
      addWarning("Base relocation entries are truncated or no longer map to file data.");
      break;
    }
    index += requestedWords;
  }
  if (skipPayload) addWarning("Base relocation HIGHADJ entry is missing its second WORD payload.");
  return entries;
};

const emptyRelocations = (warning: string): { result: PeBaseRelocationResult } => ({
  result: { blocks: [], totalEntries: 0, warnings: [warning] }
});

const validateBaseRelocationDirectory = (
  reader: FileRangeReader, dataDirs: PeDataDirectory[], rvaToOff: RvaToOffset
): { dir: PeDataDirectory } | { result: PeBaseRelocationResult | null } => {
  const dir = dataDirs.find(directory => directory.name === "BASERELOC");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return { result: null };
  if (dir.rva === 0) {
    return emptyRelocations("Base relocation directory has a non-zero size but RVA is 0.");
  }
  if (dir.size < IMAGE_BASE_RELOCATION_HEADER_SIZE) {
    return emptyRelocations("Base relocation directory is smaller than the 8-byte IMAGE_BASE_RELOCATION header.");
  }
  const base = rvaToOff(dir.rva);
  if (base == null) return emptyRelocations("Base relocation directory RVA does not map to file data.");
  if (base < 0 || base >= reader.size) {
    return emptyRelocations("Base relocation directory starts outside file data.");
  }
  return { dir };
};

const readRelocationHeader = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset, blockRva: number,
  addWarning: (message: string) => void
): Promise<{ pageRva: number; blockSize: number } | null> => {
  if (rvaToOff(blockRva) == null) {
    addWarning("Base relocation block RVA does not map to file data.");
    return null;
  }
  const view = await readMappedRvaPrefix(reader, blockRva, IMAGE_BASE_RELOCATION_HEADER_SIZE, rvaToOff);
  if (view.byteLength < IMAGE_BASE_RELOCATION_HEADER_SIZE) {
    addWarning("Base relocation block header is truncated.");
    return null;
  }
  const pageRva = view.getUint32(0, true);
  const blockSize = view.getUint32(4, true);
  if ((pageRva & (BASE_RELOCATION_PAGE_SIZE - 1)) !== 0) {
    addWarning("Base relocation PageRVA is not aligned to a 4 KiB page.");
  }
  if (!blockSize) {
    addWarning("Base relocation block size is 0, so parsing stops at an invalid terminator.");
    return null;
  }
  if (blockSize < IMAGE_BASE_RELOCATION_HEADER_SIZE) {
    addWarning("Base relocation block size is smaller than the 8-byte IMAGE_BASE_RELOCATION header.");
    return null;
  }
  return { pageRva, blockSize };
};

const parseBaseRelocationBlock = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  dir: PeDataDirectory,
  rel: number,
  addWarning: (message: string) => void
): Promise<{
  block: PeBaseRelocationBlock | null;
  nextRel: number;
  stop: boolean;
}> => {
  const blockRva = dir.rva + rel;
  const header = await readRelocationHeader(reader, rvaToOff, blockRva, addWarning);
  if (!header) return { block: null, nextRel: rel, stop: true };
  const { pageRva, blockSize } = header;
  if (blockSize > dir.size - rel) {
    addWarning("Base relocation block is truncated by the declared relocation directory size.");
  }
  const availableBlockBytes = Math.min(blockSize, dir.size - rel);
  const availableEntries = Math.floor(
    Math.max(0, availableBlockBytes - IMAGE_BASE_RELOCATION_HEADER_SIZE) /
      IMAGE_BASE_RELOCATION_ENTRY_SIZE
  );
  const entries = await parseRelocationEntries(reader, rvaToOff,
    blockRva + IMAGE_BASE_RELOCATION_HEADER_SIZE, availableEntries, addWarning);
  const nextRel = rel + blockSize;
  return {
    block: { pageRva, size: blockSize, count: entries.length, entries },
    nextRel,
    stop: (nextRel & 3) !== 0
  };
};

export async function parseBaseRelocations(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<PeBaseRelocationResult | null> {
  const validation = validateBaseRelocationDirectory(reader, dataDirs, rvaToOff);
  if ("result" in validation) return validation.result;
  const { dir } = validation;
  const blocks: PeBaseRelocationBlock[] = [];
  const warnings: string[] = [];
  const addWarning = (message: string): void => {
    if (!warnings.includes(message)) warnings.push(message);
  };
  let rel = 0;
  let totalEntries = 0;
  while (rel + IMAGE_BASE_RELOCATION_HEADER_SIZE <= dir.size) {
    const parsed = await parseBaseRelocationBlock(reader, rvaToOff, dir, rel, addWarning);
    if (!parsed.block) break;
    blocks.push(parsed.block);
    totalEntries += parsed.block.entries.length;
    if (parsed.stop) {
      addWarning("Base relocation blocks must begin on a 32-bit boundary; stopping at misaligned block size.");
      break;
    }
    rel = parsed.nextRel;
  }
  if (rel < dir.size && dir.size - rel < IMAGE_BASE_RELOCATION_HEADER_SIZE) {
    addWarning("Base relocation directory ends with a truncated block header.");
  }
  return warnings.length ? { blocks, totalEntries, warnings } : { blocks, totalEntries };
}
