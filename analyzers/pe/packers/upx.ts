"use strict";

import type { PeSection } from "../types.js";
import { upxAdler32 } from "./upx-adler32.js";
import { decompressUpxLzma } from "./upx-lzma.js";
import { decompressUpxNrv } from "./upx-nrv.js";
import { parseUpxPackHeader, type UpxPackHeader } from "./upx-pack-header.js";
import type {
  PePackerDetectorResult,
  PePackerFinding,
  UpxDetectorInput
} from "./types.js";

interface UpxCandidate {
  offset: number;
  header: UpxPackHeader;
  packedStart: number;
  packedEnd: number;
}

// PE unpacking in upstream UPX searches from 64 bytes before a raw section
// boundary through a bounded loader prefix, independent of section names.
// https://github.com/upx/upx/blob/devel/src/pefile.cpp
const SEARCH_PREFIX_BYTES = 64;
const SEARCH_WINDOW_BYTES = 1024;
// Full verification allocates the declared output in the browser. Bound it so
// malformed PackHeaders cannot force multi-gigabyte allocations.
const MAX_UPX_UNPACKED_BYTES = 256 * 1024 * 1024;
const UPX_MAGIC = Uint8Array.of(0x55, 0x50, 0x58, 0x21);

const sectionRawEnd = (section: PeSection): number | null => {
  const start = section.pointerToRawData >>> 0;
  const size = section.sizeOfRawData >>> 0;
  const end = start + size;
  return Number.isSafeInteger(end) ? end : null;
};

const payloadFitsSection = (
  sections: PeSection[],
  packedStart: number,
  packedEnd: number,
  fileSize: number
): boolean => packedEnd <= fileSize && sections.some(section => {
  const start = section.pointerToRawData >>> 0;
  const end = sectionRawEnd(section);
  return end != null && start <= packedStart && packedEnd <= end;
});

const candidateSearchRanges = (
  sections: PeSection[],
  fileSize: number
): Array<{ start: number; end: number }> => {
  const ranges = sections.flatMap(section => {
    const rawStart = section.pointerToRawData >>> 0;
    const rawSize = section.sizeOfRawData >>> 0;
    if (rawSize === 0 || rawStart >= fileSize) return [];
    return [{
      start: Math.max(0, rawStart - SEARCH_PREFIX_BYTES),
      end: Math.min(fileSize, rawStart + Math.min(rawSize, SEARCH_WINDOW_BYTES))
    }];
  });
  return ranges.filter((range, index) =>
    ranges.findIndex(other => other.start === range.start && other.end === range.end) === index
  );
};

const magicAt = (bytes: Uint8Array, offset: number): boolean =>
  UPX_MAGIC.every((byte, index) => bytes[offset + index] === byte);

const findMagicOffsets = (bytes: Uint8Array): number[] => {
  const offsets: number[] = [];
  for (let offset = 0; offset <= bytes.byteLength - UPX_MAGIC.byteLength; offset += 1) {
    if (magicAt(bytes, offset)) offsets.push(offset);
  }
  return offsets;
};

const formatOffset = (offset: number): string => `0x${offset.toString(16)}`;

const collectCandidates = async (
  input: UpxDetectorInput,
  warnings: string[]
): Promise<UpxCandidate[]> => {
  const candidates: UpxCandidate[] = [];
  const seen = new Set<number>();
  for (const range of candidateSearchRanges(input.sections, input.reader.size)) {
    const view = await input.reader.read(range.start, range.end - range.start);
    const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    for (const relativeOffset of findMagicOffsets(bytes)) {
      const offset = range.start + relativeOffset;
      if (seen.has(offset)) continue;
      seen.add(offset);
      const result = parseUpxPackHeader(view, relativeOffset, input.imagePointerBytes);
      if (!result || "error" in result) {
        if (result) warnings.push(`${result.error} Candidate offset: ${formatOffset(offset)}.`);
        continue;
      }
      const packedStart = offset + result.header.headerSize;
      const packedEnd = packedStart + result.header.packedSize;
      if (!Number.isSafeInteger(packedEnd) || !payloadFitsSection(
        input.sections,
        packedStart,
        packedEnd,
        input.reader.size
      )) {
        warnings.push(`UPX packed range at ${formatOffset(packedStart)} is outside its PE section.`);
        continue;
      }
      candidates.push({ offset, header: result.header, packedStart, packedEnd });
    }
  }
  return candidates;
};

const methodLabel = (method: number): string => {
  if (method === 14) return "LZMA";
  const family = method <= 4 ? "NRV2B" : method <= 7 ? "NRV2D" : "NRV2E";
  const widths = ["LE32", "8-bit", "LE16"];
  return `${family} ${widths[(method - 2) % 3] ?? "unknown"}`;
};

const unpackCandidate = async (candidate: UpxCandidate, packed: Uint8Array): Promise<Uint8Array> =>
  candidate.header.method === 14
    ? decompressUpxLzma(packed, candidate.header.unpackedSize, candidate.header.level)
    : decompressUpxNrv(packed, candidate.header.unpackedSize, candidate.header.method);

const createFinding = (candidate: UpxCandidate): PePackerFinding => ({
  id: "upx",
  name: "UPX executable packer",
  kind: "executable-packer",
  confidence: "high",
  evidence: [
    "A structurally valid PE PackHeader has valid bounds.",
    candidate.header.headerChecksum == null
      ? "Legacy PackHeader has no header checksum field."
      : "PackHeader checksum matches.",
    "The declared compression method decoded the complete packed stream.",
    "Packed and unpacked Adler-32 values both match PackHeader."
  ],
  details: [
    { label: "PackHeader offset", kind: "offset", value: candidate.offset },
    {
      label: "Packed data range",
      kind: "range",
      start: candidate.packedStart,
      end: candidate.packedEnd
    },
    { label: "UPX format", kind: "number", value: candidate.header.format },
    { label: "UPX version", kind: "number", value: candidate.header.version },
    { label: "Compression", kind: "text", value: methodLabel(candidate.header.method) },
    { label: "Compression level", kind: "number", value: candidate.header.level },
    { label: "Packed size", kind: "bytes", value: candidate.header.packedSize },
    { label: "Unpacked size", kind: "bytes", value: candidate.header.unpackedSize },
    { label: "Original file size", kind: "bytes", value: candidate.header.originalFileSize },
    { label: "Filter", kind: "number", value: candidate.header.filter },
    { label: "Filter parameter", kind: "number", value: candidate.header.filterParameter }
  ]
});

const verifyCandidate = async (
  input: UpxDetectorInput,
  candidate: UpxCandidate,
  warnings: string[]
): Promise<PePackerFinding | null> => {
  if (candidate.header.unpackedSize > MAX_UPX_UNPACKED_BYTES) {
    warnings.push(`UPX unpacked size at ${formatOffset(candidate.offset)} exceeds the browser limit.`);
    return null;
  }
  const packed = await input.reader.readBytes(candidate.packedStart, candidate.header.packedSize);
  if (packed.byteLength !== candidate.header.packedSize) {
    warnings.push(`UPX packed data at ${formatOffset(candidate.packedStart)} is truncated.`);
    return null;
  }
  if (upxAdler32(packed) !== candidate.header.packedAdler32) {
    warnings.push(`UPX packed Adler-32 at ${formatOffset(candidate.offset)} does not match.`);
    return null;
  }
  try {
    const unpacked = await unpackCandidate(candidate, packed);
    if (upxAdler32(unpacked) !== candidate.header.unpackedAdler32) {
      warnings.push(`UPX unpacked Adler-32 at ${formatOffset(candidate.offset)} does not match.`);
      return null;
    }
    return createFinding(candidate);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    warnings.push(`UPX decompression at ${formatOffset(candidate.offset)} failed: ${message}`);
    return null;
  }
};

export const detectUpx = async (input: UpxDetectorInput): Promise<PePackerDetectorResult> => {
  const findings: PePackerFinding[] = [];
  const warnings: string[] = [];
  for (const candidate of await collectCandidates(input, warnings)) {
    const finding = await verifyCandidate(input, candidate, warnings);
    if (finding) findings.push(finding);
  }
  return { findings, warnings: [...new Set(warnings)] };
};
