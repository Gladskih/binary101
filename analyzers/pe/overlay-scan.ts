"use strict";

import { detectBinaryType } from "../detect-binary-type.js";
import type { FileRangeReader } from "../file-range-reader.js";
import { parseRar } from "../rar/index.js";
import type { FileRange } from "./layout/file-ranges.js";
import type { PeOverlayFinding, PeOverlayRange, PeOverlayScanOptions } from "./overlay.js";
import {
  detectEmbeddedCandidateType,
  EMBEDDED_BMP_LABEL,
  EMBEDDED_CAB_LABEL,
  EMBEDDED_EXECUTABLE_LABEL,
  EMBEDDED_MIDI_LABEL,
  EMBEDDED_RAR_LABEL,
  EMBEDDED_SEVEN_ZIP_LABEL,
  isEmbeddedCandidateStartByte,
  readEmbeddedBmpFileSize,
  readEmbeddedCabinetFileSize,
  readEmbeddedMidiFileSize,
  readEmbeddedSevenZipFileSize
} from "./overlay-embedded.js";

// Match the project FileRangeReader cache window so scans reuse cached slices efficiently.
const SCAN_CHUNK_BYTES = 64 * 1024;
const PROBE_LOOKAHEAD_BYTES = 64 * 1024;
const OVERLAY_PREFIX_VALIDATE_BYTES = 64;
const OVERLAY_MIDI_VALIDATE_BYTES = 64 * 1024;
const CAB_SIZE_READ_BYTES = 12;

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

const getOverlayValidationBytes = (label: string): number =>
  label === EMBEDDED_MIDI_LABEL ? OVERLAY_MIDI_VALIDATE_BYTES : OVERLAY_PREFIX_VALIDATE_BYTES;

const detectRangeAtOffset = async (
  file: File,
  range: FileRange,
  offset: number
): Promise<string | null> => {
  const label = await detectBinaryType(createOverlaySliceFile(file, { start: offset, end: range.end }));
  if (label === "Unknown binary type" || label === "MS-DOS MZ executable" || label === "Text file") return null;
  if (label !== EMBEDDED_BMP_LABEL && label !== EMBEDDED_MIDI_LABEL) return label;
  const prefixEnd = Math.min(range.end, offset + getOverlayValidationBytes(label));
  const prefix = new DataView(await file.slice(offset, prefixEnd).arrayBuffer());
  if (label === EMBEDDED_BMP_LABEL && readEmbeddedBmpFileSize(prefix, range.end - offset) == null) return null;
  if (label === EMBEDDED_MIDI_LABEL && readEmbeddedMidiFileSize(prefix, range.end - offset) == null) return null;
  return label;
};

const hasEmbeddedRarArchive = async (
  file: File,
  range: FileRange,
  offset: number
): Promise<boolean> => {
  const rar = await parseRar(createOverlaySliceFile(file, { start: offset, end: range.end }));
  return rar.isRar && rar.mainHeader != null;
};

const resolveEmbeddedCandidateType = async (
  file: File,
  range: FileRange,
  offset: number,
  candidateType: string
): Promise<string | null> => {
  if (candidateType === EMBEDDED_EXECUTABLE_LABEL) return detectRangeAtOffset(file, range, offset);
  if (candidateType === EMBEDDED_RAR_LABEL && !await hasEmbeddedRarArchive(file, range, offset)) {
    return null;
  }
  return candidateType;
};

const throwIfAborted = (signal: AbortSignal | undefined): void => {
  if (signal?.aborted) throw new Error("PE overlay scan aborted.");
};

const reportProgress = (
  range: FileRange,
  findings: PeOverlayFinding[],
  bytesScanned: number,
  options: PeOverlayScanOptions
): void => {
  options.onProgress?.({
    stage: "scanning",
    bytesScanned: Math.min(range.end - range.start, bytesScanned),
    totalBytes: range.end - range.start,
    findingsFound: findings.length
  });
};

const readCabinetEnd = async (
  reader: FileRangeReader,
  range: FileRange,
  start: number
): Promise<number | null> => {
  if (range.end - start < CAB_SIZE_READ_BYTES) return null;
  const view = await reader.read(start, CAB_SIZE_READ_BYTES);
  const cabinetSize = readEmbeddedCabinetFileSize(view, range.end - start);
  return cabinetSize == null ? null : start + cabinetSize;
};

const readBitmapEnd = async (
  reader: FileRangeReader,
  range: FileRange,
  start: number
): Promise<number | null> => {
  const view = await reader.read(start, Math.min(OVERLAY_PREFIX_VALIDATE_BYTES, range.end - start));
  const bitmapSize = readEmbeddedBmpFileSize(view, range.end - start);
  return bitmapSize == null ? null : start + bitmapSize;
};

const readMidiEnd = async (
  reader: FileRangeReader,
  range: FileRange,
  start: number
): Promise<number | null> => {
  const view = await reader.read(start, Math.min(OVERLAY_MIDI_VALIDATE_BYTES, range.end - start));
  const midiSize = readEmbeddedMidiFileSize(view, range.end - start);
  return midiSize == null ? null : start + midiSize;
};

const readSevenZipEnd = async (
  reader: FileRangeReader,
  range: FileRange,
  start: number
): Promise<number | null> => {
  const view = await reader.read(start, Math.min(OVERLAY_PREFIX_VALIDATE_BYTES, range.end - start));
  const archiveSize = readEmbeddedSevenZipFileSize(view, range.end - start);
  return archiveSize == null ? null : start + archiveSize;
};

const createOverlayFinding = async (
  reader: FileRangeReader,
  range: FileRange,
  start: number,
  detectedType: string
): Promise<PeOverlayFinding> => {
  const cabinetEnd = detectedType === EMBEDDED_CAB_LABEL ? await readCabinetEnd(reader, range, start) : null;
  const bitmapEnd = detectedType === EMBEDDED_BMP_LABEL ? await readBitmapEnd(reader, range, start) : null;
  const midiEnd = detectedType === EMBEDDED_MIDI_LABEL ? await readMidiEnd(reader, range, start) : null;
  const sevenZipEnd = detectedType === EMBEDDED_SEVEN_ZIP_LABEL ? await readSevenZipEnd(reader, range, start) : null;
  const end = cabinetEnd ?? bitmapEnd ?? midiEnd ?? sevenZipEnd ?? range.end;
  return {
    start,
    end,
    size: end - start,
    detectedType,
    endDescription: cabinetEnd
      ? "End comes from the CAB CFHEADER.cbCabinet size field."
      : bitmapEnd
        ? "End comes from the BMP file header bfSize field."
        : midiEnd
          ? "End comes from the Standard MIDI track chunk length fields."
          : sevenZipEnd
            ? "End comes from the 7z SignatureHeader NextHeaderOffset and NextHeaderSize fields."
            : "End is the end of the true overlay range; exact embedded payload length is not known."
  };
};

const findEmbeddedFindings = async (
  file: File,
  reader: FileRangeReader,
  range: FileRange,
  options: PeOverlayScanOptions
): Promise<PeOverlayFinding[]> => {
  const findings: PeOverlayFinding[] = [];
  let cursor = range.start;
  reportProgress(range, findings, 0, options);
  while (cursor < range.end) {
    throwIfAborted(options.signal);
    const searchableBytes = Math.min(SCAN_CHUNK_BYTES, range.end - cursor);
    const readBytes = Math.min(searchableBytes + PROBE_LOOKAHEAD_BYTES, range.end - cursor);
    const view = await reader.read(cursor, readBytes);
    const foundInChunk = await scanChunk(file, reader, range, view, cursor, searchableBytes, findings, options);
    cursor = foundInChunk ?? cursor + searchableBytes;
    reportProgress(range, findings, cursor - range.start, options);
  }
  options.onProgress?.({
    stage: "done",
    bytesScanned: range.end - range.start,
    totalBytes: range.end - range.start,
    findingsFound: findings.length
  });
  return findings;
};

const scanChunk = async (
  file: File,
  reader: FileRangeReader,
  range: FileRange,
  view: DataView,
  cursor: number,
  searchableBytes: number,
  findings: PeOverlayFinding[],
  options: PeOverlayScanOptions
): Promise<number | null> => {
  for (let index = 0; index < searchableBytes; index += 1) {
    throwIfAborted(options.signal);
    if (!isEmbeddedCandidateStartByte(view.getUint8(index))) continue;
    const probeView = new DataView(view.buffer, view.byteOffset + index, view.byteLength - index);
    const candidateType = detectEmbeddedCandidateType(probeView, range.end - cursor - index);
    if (!candidateType) continue;
    const detectedOffset = cursor + index;
    const detectedType = await resolveEmbeddedCandidateType(
      file,
      range,
      detectedOffset,
      candidateType
    );
    if (!detectedType) continue;
    const finding = await createOverlayFinding(reader, range, detectedOffset, detectedType);
    findings.push(finding);
    return Math.max(detectedOffset + 1, finding.end);
  }
  return null;
};

export const scanPeOverlayRange = async (
  file: File,
  reader: FileRangeReader,
  range: PeOverlayRange,
  options: PeOverlayScanOptions = {}
): Promise<PeOverlayRange> => {
  const findings = await findEmbeddedFindings(file, reader, range, options);
  return {
    ...range,
    findings,
    embeddedScan: { status: "complete", scannedBytes: range.end - range.start }
  };
};
