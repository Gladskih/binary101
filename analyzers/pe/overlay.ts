"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { PeDataDirectory, PeSection } from "./types.js";
import { normalizeFileRanges, type FileRange } from "./layout/file-ranges.js";
import {
  COFF_SECTION_HEADER_BYTE_LENGTH,
  COFF_SYMBOL_RECORD_BYTE_LENGTH
} from "../coff/layout.js";

export interface PeOverlayRange {
  start: number;
  end: number;
  size: number;
  findings: PeOverlayFinding[];
  embeddedScan?: PeOverlayEmbeddedScan;
}

export interface PeOverlayFinding {
  start: number;
  end: number;
  size: number;
  detectedType: string;
  endDescription: string;
}

export interface PeOverlayEmbeddedScan {
  status: "complete";
  scannedBytes: number;
}

export interface PeOverlayAnalysis {
  ranges: PeOverlayRange[];
  warnings?: string[];
}

export type PeOverlayScanProgress = {
  stage: "scanning" | "done";
  bytesScanned: number;
  totalBytes: number;
  findingsFound: number;
};

export type PeOverlayScanOptions = {
  signal?: AbortSignal;
  onProgress?: (progress: PeOverlayScanProgress) => void;
};

type PeOverlayInputs = {
  file: File;
  reader: FileRangeReader;
  optionalHeaderOffset: number;
  optionalHeaderSize: number;
  sectionCount: number;
  declaredSizeOfHeaders: number;
  sections: PeSection[];
  trailingAlignmentPaddingSize?: number;
  dataDirs: PeDataDirectory[];
  debugRawDataRanges?: FileRange[];
  pointerToSymbolTable: number;
  numberOfSymbols: number;
  coffStringTableSize?: number;
};

const getCoffStringTableOffset = (pointerToSymbolTable: number, numberOfSymbols: number): number | null => {
  if (!pointerToSymbolTable || !numberOfSymbols) return null;
  const symbolTableEnd = pointerToSymbolTable + numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  return Number.isSafeInteger(symbolTableEnd) ? symbolTableEnd : null;
};

const computeCandidateTailRange = (inputs: PeOverlayInputs): FileRange | null => {
  const headerSpanEnd = Math.max(
    inputs.optionalHeaderOffset + inputs.optionalHeaderSize,
    inputs.optionalHeaderOffset +
      inputs.optionalHeaderSize +
      (inputs.sectionCount >>> 0) * COFF_SECTION_HEADER_BYTE_LENGTH
  );
  const normalizedSizeOfHeaders =
    Number.isSafeInteger(inputs.declaredSizeOfHeaders) && inputs.declaredSizeOfHeaders > 0
      ? Math.min(inputs.reader.size, inputs.declaredSizeOfHeaders >>> 0)
      : headerSpanEnd;
  let rawImageEnd = Math.max(headerSpanEnd, normalizedSizeOfHeaders);
  for (const section of inputs.sections) {
    rawImageEnd = Math.max(rawImageEnd, (section.pointerToRawData >>> 0) + (section.sizeOfRawData >>> 0));
  }
  return inputs.reader.size > rawImageEnd ? { start: rawImageEnd, end: inputs.reader.size } : null;
};

const addKnownRange = (ranges: FileRange[], range: FileRange, tailStart: number, tailEnd: number): void => {
  const start = Math.max(tailStart, range.start);
  const end = Math.min(tailEnd, range.end);
  if (end > start) ranges.push({ start, end });
};

const getKnownTailRanges = (inputs: PeOverlayInputs, tailStart: number, tailEnd: number): FileRange[] => {
  const ranges: FileRange[] = [];
  const securityDir = inputs.dataDirs.find(dir => dir.name === "SECURITY");
  if (securityDir?.size) {
    addKnownRange(
      ranges,
      {
        start: securityDir.rva >>> 0,
        end: (securityDir.rva >>> 0) + (securityDir.size >>> 0)
      },
      tailStart,
      tailEnd
    );
  }
  for (const range of inputs.debugRawDataRanges ?? []) addKnownRange(ranges, range, tailStart, tailEnd);
  if (inputs.pointerToSymbolTable) {
    addKnownRange(
      ranges,
      {
        start: inputs.pointerToSymbolTable >>> 0,
        end: (inputs.pointerToSymbolTable >>> 0) +
          (inputs.numberOfSymbols >>> 0) * COFF_SYMBOL_RECORD_BYTE_LENGTH
      },
      tailStart,
      tailEnd
    );
  }
  const stringTableOffset = getCoffStringTableOffset(inputs.pointerToSymbolTable, inputs.numberOfSymbols);
  if (stringTableOffset != null && inputs.coffStringTableSize != null) {
    addKnownRange(
      ranges,
      { start: stringTableOffset, end: stringTableOffset + (inputs.coffStringTableSize >>> 0) },
      tailStart,
      tailEnd
    );
  }
  if (inputs.trailingAlignmentPaddingSize) {
    addKnownRange(
      ranges,
      { start: tailEnd - inputs.trailingAlignmentPaddingSize, end: tailEnd },
      tailStart,
      tailEnd
    );
  }
  return normalizeFileRanges(ranges);
};

export const getUnexplainedOverlayRanges = (inputs: PeOverlayInputs): FileRange[] => {
  const candidateTailRange = computeCandidateTailRange(inputs);
  if (!candidateTailRange) return [];
  const knownRanges = getKnownTailRanges(inputs, candidateTailRange.start, candidateTailRange.end);
  const unexplained: FileRange[] = [];
  let cursor = candidateTailRange.start;
  for (const range of knownRanges) {
    if (range.start > cursor) unexplained.push({ start: cursor, end: range.start });
    cursor = Math.max(cursor, range.end);
  }
  if (cursor < candidateTailRange.end) unexplained.push({ start: cursor, end: candidateTailRange.end });
  return unexplained;
};

export const analyzePeOverlay = async (inputs: PeOverlayInputs): Promise<PeOverlayAnalysis | null> => {
  const ranges = getUnexplainedOverlayRanges(inputs).map(range => ({
    ...range,
    size: range.end - range.start,
    findings: []
  }));
  return ranges.length ? { ranges } : null;
};
