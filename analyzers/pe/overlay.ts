"use strict";

import { detectBinaryType } from "../detect-binary-type.js";
import type { FileRangeReader } from "../file-range-reader.js";
import type { PeDataDirectory, PeSection } from "./types.js";
import { normalizeFileRanges, type FileRange } from "./layout/file-ranges.js";
import {
  detectEmbeddedCandidateType,
  EMBEDDED_EXECUTABLE_LABEL,
  isEmbeddedCandidateStartByte
} from "./overlay-embedded.js";

export interface PeOverlayRange {
  start: number;
  end: number;
  size: number;
  findings: PeOverlayFinding[];
}

export interface PeOverlayFinding {
  start: number;
  end: number;
  size: number;
  detectedType: string;
  endDescription: string;
}

export interface PeOverlayAnalysis {
  ranges: PeOverlayRange[];
  warnings?: string[];
}

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

// Microsoft PE/COFF: each symbol-table record is 18 bytes.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table
const IMAGE_SYMBOL_SIZE = 18;
// Microsoft PE format, "Section Table": IMAGE_SECTION_HEADER records are 40 bytes.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
const IMAGE_SECTION_HEADER_SIZE = 40;
// Keep automatic embedded scans bounded; larger tails remain downloadable and report a warning.
const MAX_EMBEDDED_SIGNATURE_SCAN_BYTES = 1024 * 1024;
// Match the project FileRangeReader cache window so scans reuse cached slices efficiently.
const SCAN_CHUNK_BYTES = 64 * 1024;
const PROBE_LOOKAHEAD_BYTES = 64 * 1024;
// [MS-CAB] CFHEADER starts with "MSCF" and stores cbCabinet at byte offset 8.
// https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/[ms-cab].pdf
const CAB_SIGNATURE = 0x4d534346;
const CAB_CBCABINET_OFFSET = 8;
const CAB_SIZE_READ_BYTES = 12;
const CAB_MIN_CFHEADER_BYTES = 36;
const CAB_LABEL = "Microsoft Cabinet archive (CAB)";

const getCoffStringTableOffset = (pointerToSymbolTable: number, numberOfSymbols: number): number | null => {
  if (!pointerToSymbolTable || !numberOfSymbols) return null;
  const symbolTableEnd = pointerToSymbolTable + numberOfSymbols * IMAGE_SYMBOL_SIZE;
  return Number.isSafeInteger(symbolTableEnd) ? symbolTableEnd : null;
};

const computeCandidateTailRange = (inputs: PeOverlayInputs): FileRange | null => {
  const headerSpanEnd = Math.max(
    inputs.optionalHeaderOffset + inputs.optionalHeaderSize,
    inputs.optionalHeaderOffset + inputs.optionalHeaderSize + (inputs.sectionCount >>> 0) * IMAGE_SECTION_HEADER_SIZE
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
        end: (inputs.pointerToSymbolTable >>> 0) + (inputs.numberOfSymbols >>> 0) * IMAGE_SYMBOL_SIZE
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

const createOverlaySliceFile = (file: File, range: FileRange): File => {
  const blob = file.slice(range.start, range.end, "application/octet-stream");
  const name = `${file.name || "file"}.overlay-${range.start.toString(16)}.bin`;
  if (typeof File === "function") return new File([blob], name, { type: "application/octet-stream" });
  return Object.assign(blob, {
    name,
    lastModified: file.lastModified,
    webkitRelativePath: ""
  }) as File;
};

const detectRangeAtOffset = async (
  file: File,
  range: FileRange,
  offset: number
): Promise<string | null> => {
  const label = await detectBinaryType(createOverlaySliceFile(file, { start: offset, end: range.end }));
  return label === "Unknown binary type" || label === "MS-DOS MZ executable" ? null : label;
};

const findEmbeddedFinding = async (
  file: File,
  reader: FileRangeReader,
  range: FileRange
): Promise<PeOverlayFinding | null> => {
  const scanEnd = Math.min(range.end, range.start + MAX_EMBEDDED_SIGNATURE_SCAN_BYTES);
  let cursor = range.start + 1;
  while (cursor < scanEnd) {
    const searchableBytes = Math.min(SCAN_CHUNK_BYTES, scanEnd - cursor);
    const readBytes = Math.min(searchableBytes + PROBE_LOOKAHEAD_BYTES, range.end - cursor);
    const view = await reader.read(cursor, readBytes);
    for (let index = 0; index < searchableBytes; index += 1) {
      if (!isEmbeddedCandidateStartByte(view.getUint8(index))) continue;
      const probeView = new DataView(view.buffer, view.byteOffset + index, view.byteLength - index);
      const candidateType = detectEmbeddedCandidateType(probeView, range.end - cursor - index);
      if (!candidateType) continue;
      const detectedOffset = cursor + index;
      const detectedType = candidateType === EMBEDDED_EXECUTABLE_LABEL
        ? await detectRangeAtOffset(file, range, detectedOffset)
        : candidateType;
      if (!detectedType) continue;
      return createOverlayFinding(reader, range, detectedOffset, detectedType);
    }
    cursor += searchableBytes;
  }
  return null;
};

const readCabinetEnd = async (
  reader: FileRangeReader,
  range: FileRange,
  start: number
): Promise<number | null> => {
  if (range.end - start < CAB_SIZE_READ_BYTES) return null;
  const view = await reader.read(start, CAB_SIZE_READ_BYTES);
  if (view.byteLength < CAB_SIZE_READ_BYTES || view.getUint32(0, false) !== CAB_SIGNATURE) return null;
  const cabinetSize = view.getUint32(CAB_CBCABINET_OFFSET, true);
  if (cabinetSize < CAB_MIN_CFHEADER_BYTES || cabinetSize > range.end - start) return null;
  return start + cabinetSize;
};

const createOverlayFinding = async (
  reader: FileRangeReader,
  range: FileRange,
  start: number,
  detectedType: string
): Promise<PeOverlayFinding> => {
  const cabinetEnd = detectedType === CAB_LABEL ? await readCabinetEnd(reader, range, start) : null;
  const end = cabinetEnd ?? range.end;
  return {
    start,
    end,
    size: end - start,
    detectedType,
    endDescription: cabinetEnd
      ? "End comes from the CAB CFHEADER.cbCabinet size field."
      : "End is the end of the true overlay range; exact embedded payload length is not known."
  };
};

const detectOverlayFindings = async (
  file: File,
  reader: FileRangeReader,
  range: FileRange
): Promise<PeOverlayFinding[]> => {
  const directLabel = await detectRangeAtOffset(file, range, range.start);
  if (directLabel) return [await createOverlayFinding(reader, range, range.start, directLabel)];
  const embeddedFinding = await findEmbeddedFinding(file, reader, range);
  return embeddedFinding ? [embeddedFinding] : [];
};

export const analyzePeOverlay = async (inputs: PeOverlayInputs): Promise<PeOverlayAnalysis | null> => {
  const warnings: string[] = [];
  const ranges = await Promise.all(
    getUnexplainedOverlayRanges(inputs).map(async range => {
      let findings: PeOverlayFinding[] = [];
      try {
        findings = await detectOverlayFindings(inputs.file, inputs.reader, range);
      } catch (error) {
        const message = error instanceof Error && error.message ? error.message : String(error);
        warnings.push(`Overlay at 0x${range.start.toString(16)} could not be recognized: ${message}`);
      }
      if (range.end - range.start > MAX_EMBEDDED_SIGNATURE_SCAN_BYTES && !findings.length) {
        warnings.push(`Overlay at 0x${range.start.toString(16)} was scanned for embedded signatures only for the first ${MAX_EMBEDDED_SIGNATURE_SCAN_BYTES} bytes.`);
      }
      return { ...range, size: range.end - range.start, findings };
    })
  );
  if (!ranges.length && !warnings.length) return null;
  return warnings.length ? { ranges, warnings } : { ranges };
};
