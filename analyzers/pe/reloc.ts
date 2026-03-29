"use strict";

import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import type { PeDataDirectory, RvaToOffset } from "./types.js";

const IMAGE_REL_BASED_HIGHADJ = 4;
// Microsoft PE/COFF: IMAGE_BASE_RELOCATION consists of an 8-byte header followed by WORD entries.
const IMAGE_BASE_RELOCATION_HEADER_SIZE = 8;
const IMAGE_BASE_RELOCATION_ENTRY_SIZE = Uint16Array.BYTES_PER_ELEMENT;

type RelocationEntrySpan = {
  firstEntryIndex: number;
  fileOffset: number;
  wordCount: number;
};

type RelocationEntrySpanView = RelocationEntrySpan & {
  view: DataView;
};

const collectRelocationEntrySpans = (
  availableEntries: number,
  blockRva: number,
  rvaToOff: RvaToOffset,
  fileSize: number,
  addWarning: (message: string) => void
): RelocationEntrySpan[] | null => {
  const spans: RelocationEntrySpan[] = [];
  for (let entryIndex = 0; entryIndex < availableEntries; entryIndex += 1) {
    // Chromium profiling showed that reading each WORD relocation entry
    // separately made `.reloc` alone issue 132,746 tiny
    // File.slice().arrayBuffer() calls. Keep per-entry RVA validation, but
    // collapse contiguous file offsets into spans and read each span once.
    const entryRva =
      (blockRva +
        IMAGE_BASE_RELOCATION_HEADER_SIZE +
        entryIndex * IMAGE_BASE_RELOCATION_ENTRY_SIZE) >>>
      0;
    const entryOffset = rvaToOff(entryRva);
    if (entryOffset == null || entryOffset < 0 || entryOffset + IMAGE_BASE_RELOCATION_ENTRY_SIZE > fileSize) {
      addWarning("Base relocation entries are truncated or no longer map to file data.");
      return null;
    }
    const previousSpan = spans[spans.length - 1];
    if (
      previousSpan &&
      entryOffset === previousSpan.fileOffset + previousSpan.wordCount * IMAGE_BASE_RELOCATION_ENTRY_SIZE
    ) {
      previousSpan.wordCount += 1;
      continue;
    }
    spans.push({
      firstEntryIndex: entryIndex,
      fileOffset: entryOffset,
      wordCount: 1
    });
  }
  return spans;
};

const readRelocationEntrySpans = async (
  reader: FileRangeReader,
  spans: RelocationEntrySpan[],
  addWarning: (message: string) => void
): Promise<RelocationEntrySpanView[] | null> => {
  const spanViews: RelocationEntrySpanView[] = [];
  for (const span of spans) {
    const byteLength = span.wordCount * IMAGE_BASE_RELOCATION_ENTRY_SIZE;
    const view = await reader.read(span.fileOffset, byteLength);
    if (view.byteLength < byteLength) {
      addWarning("Base relocation entry is truncated.");
      return null;
    }
    spanViews.push({ ...span, view });
  }
  return spanViews;
};

const parseRelocationEntries = (
  availableEntries: number,
  spanViews: RelocationEntrySpanView[],
  addWarning: (message: string) => void
): Array<{ type: number; offset: number }> => {
  const entries: Array<{ type: number; offset: number }> = [];
  let spanIndex = 0;
  let spanView = spanViews[spanIndex];
  for (let entryIndex = 0; entryIndex < availableEntries;) {
    while (
      spanView &&
      entryIndex >= spanView.firstEntryIndex + spanView.wordCount
    ) {
      spanIndex += 1;
      spanView = spanViews[spanIndex];
    }
    if (!spanView) {
      addWarning("Base relocation entries are truncated or no longer map to file data.");
      break;
    }
    const raw = spanView.view.getUint16(
      (entryIndex - spanView.firstEntryIndex) * IMAGE_BASE_RELOCATION_ENTRY_SIZE,
      true
    );
    const type = (raw >> 12) & 0xf;
    entries.push({ type, offset: raw & 0xfff });
    if (type === IMAGE_REL_BASED_HIGHADJ) {
      if (entryIndex + 1 >= availableEntries) {
        addWarning("Base relocation HIGHADJ entry is missing its second WORD payload.");
      }
      entryIndex += 2;
      continue;
    }
    entryIndex += 1;
  }
  return entries;
};

export async function parseBaseRelocations(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<{
  blocks: Array<{ pageRva: number; size: number; count: number; entries: Array<{ type: number; offset: number }> }>;
  totalEntries: number;
  warnings?: string[];
} | null> {
  const dir = dataDirs.find(d => d.name === "BASERELOC");
  if (!dir?.rva) return null;
  if (dir.size < IMAGE_BASE_RELOCATION_HEADER_SIZE) {
    return {
      blocks: [],
      totalEntries: 0,
      warnings: [
        "Base relocation directory is smaller than the 8-byte IMAGE_BASE_RELOCATION header."
      ]
    };
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    return {
      blocks: [],
      totalEntries: 0,
      warnings: ["Base relocation directory RVA does not map to file data."]
    };
  }
  if (base < 0 || base >= file.size) {
    return {
      blocks: [],
      totalEntries: 0,
      warnings: ["Base relocation directory starts outside file data."]
    };
  }
  const blocks: Array<{
    pageRva: number;
    size: number;
    count: number;
    entries: Array<{ type: number; offset: number }>;
  }> = [];
  const warnings: string[] = [];
  const addWarning = (message: string): void => {
    if (!warnings.includes(message)) warnings.push(message);
  };
  const reader = createFileRangeReader(file, 0, file.size);
  let rel = 0;
  let totalEntries = 0;
  while (rel + IMAGE_BASE_RELOCATION_HEADER_SIZE <= dir.size) {
    const blockRva = (dir.rva + rel) >>> 0;
    const blockOff = rvaToOff(blockRva >>> 0);
    if (blockOff == null) {
      addWarning("Base relocation block RVA does not map to file data.");
      break;
    }
    const dv = await reader.read(blockOff, IMAGE_BASE_RELOCATION_HEADER_SIZE);
    if (dv.byteLength < IMAGE_BASE_RELOCATION_HEADER_SIZE) {
      addWarning("Base relocation block header is truncated.");
      break;
    }
    const pageRva = dv.getUint32(0, true);
    const blockSize = dv.getUint32(4, true);
    if (!blockSize) {
      addWarning("Base relocation block size is 0, so parsing stops at an invalid terminator.");
      break;
    }
    if (blockSize < IMAGE_BASE_RELOCATION_HEADER_SIZE) {
      addWarning("Base relocation block size is smaller than the 8-byte IMAGE_BASE_RELOCATION header.");
      break;
    }
    if (blockSize > dir.size - rel) {
      addWarning("Base relocation block is truncated by the declared relocation directory size.");
    }
    const availableBlockBytes = Math.min(blockSize, dir.size - rel);
    const availableEntries = Math.floor(
      Math.max(0, availableBlockBytes - IMAGE_BASE_RELOCATION_HEADER_SIZE) /
        IMAGE_BASE_RELOCATION_ENTRY_SIZE
    );
    const entrySpans = collectRelocationEntrySpans(
      availableEntries,
      blockRva,
      rvaToOff,
      file.size,
      addWarning
    );
    const spanViews = entrySpans
      ? await readRelocationEntrySpans(reader, entrySpans, addWarning)
      : null;
    const entries = spanViews
      ? parseRelocationEntries(availableEntries, spanViews, addWarning)
      : [];
    blocks.push({ pageRva, size: blockSize, count: entries.length, entries });
    totalEntries += entries.length;
    const nextRel = rel + blockSize;
    if ((nextRel & 3) !== 0) {
      addWarning("Base relocation blocks must begin on a 32-bit boundary; stopping at misaligned block size.");
      break;
    }
    rel = nextRel;
  }
  return warnings.length ? { blocks, totalEntries, warnings } : { blocks, totalEntries };
}
