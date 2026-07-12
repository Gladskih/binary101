"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { PeOverlayAnalysis, PeOverlayFinding } from "./overlay.js";
import { findEmbeddedPayloadsInRangePrefix } from "./overlay-scan.js";
import {
  EMBEDDED_RAR_LABEL,
  EMBEDDED_SEVEN_ZIP_LABEL
} from "./overlay-embedded.js";
import type {
  PeInnoSetupFinding,
  PePackerAnalysis,
  PeNsisPackerFinding
} from "./packers/index.js";
import { subtractFileRanges, type FileRange } from "./layout/file-ranges.js";
import type { PeResources } from "./resources/index.js";
import type { ResourcePathNode } from "./resources/tree-types.js";

export type PePayloadFormat = "pe" | "rar" | "sevenzip";

export type PePayloadProvenance =
  | {
    location: "overlay";
    discovery: "archive-scan";
    association: "nsis-installer-data" | "unattributed";
    validation: "rar-end-archive" | "sevenzip-next-header";
  }
  | {
    location: "resource";
    discovery: "resource-leaf";
    resourcePath: ResourcePathNode[];
    validation: "pe-signatures";
  };

export interface PeExtractedPayload {
  end: number;
  format: PePayloadFormat;
  provenance: PePayloadProvenance;
  start: number;
}

export interface PePayloadAnalysis {
  entries: PeExtractedPayload[];
}

// Real installer inventory placed every validated 7z/RAR start within 180 KiB of its
// overlay start. One MiB preserves a wide margin while bounding automatic reads.
const AUTOMATIC_PAYLOAD_SCAN_BYTES = 1024 * 1024;
const DOS_E_LFANEW_OFFSET = 0x3c;
const DOS_HEADER_BYTES = 0x40;
const DOS_SIGNATURE = 0x5a4d;
const PE_SIGNATURE = 0x50450000;

const findResourcePePayloads = async (
  reader: FileRangeReader,
  resources: PeResources | null | undefined
): Promise<PeExtractedPayload[]> => {
  const entries: PeExtractedPayload[] = [];
  for (const path of resources?.paths ?? []) {
    const start = path.dataFileOffset;
    const end = start == null ? null : start + path.size;
    if (start == null || end == null || path.size < DOS_HEADER_BYTES ||
        !Number.isSafeInteger(end) || end > reader.size) continue;
    const dos = await reader.read(start, DOS_HEADER_BYTES);
    if (dos.byteLength < DOS_HEADER_BYTES || dos.getUint16(0, true) !== DOS_SIGNATURE) continue;
    const peOffset = dos.getUint32(DOS_E_LFANEW_OFFSET, true);
    if (peOffset < DOS_HEADER_BYTES || peOffset > path.size - Uint32Array.BYTES_PER_ELEMENT) continue;
    const signature = await reader.read(start + peOffset, Uint32Array.BYTES_PER_ELEMENT);
    if (signature.byteLength === 4 && signature.getUint32(0, false) === PE_SIGNATURE) {
      entries.push({
        start,
        end,
        format: "pe",
        provenance: {
          location: "resource",
          discovery: "resource-leaf",
          resourcePath: path.nodes,
          validation: "pe-signatures"
        }
      });
    }
  }
  return entries;
};

const payloadFormat = (finding: PeOverlayFinding): PePayloadFormat | null => {
  if (finding.detectedType === EMBEDDED_SEVEN_ZIP_LABEL) return "sevenzip";
  if (finding.detectedType === EMBEDDED_RAR_LABEL) return "rar";
  return null;
};

const nsisFindings = (packers: PePackerAnalysis | null | undefined): PeNsisPackerFinding[] =>
  packers?.reports
    .find(report => report.id === "nsis-installer")
    ?.findings.filter(finding => finding.id === "nsis-installer") ?? [];

const innoFindings = (packers: PePackerAnalysis | null | undefined): PeInnoSetupFinding[] =>
  packers?.reports
    .find(report => report.id === "inno-setup")
    ?.findings.filter(finding => finding.id === "inno-setup") ?? [];

const overlayPayloadProvenance = (
  finding: PeOverlayFinding,
  installers: PeNsisPackerFinding[]
): Extract<PePayloadProvenance, { location: "overlay" }> =>
  installers.some(installer =>
    finding.start >= installer.firstHeaderOffset &&
    finding.end <= installer.firstHeaderOffset + installer.followingDataSize
  ) ? {
      location: "overlay",
      discovery: "archive-scan",
      association: "nsis-installer-data",
      validation: finding.detectedType === EMBEDDED_RAR_LABEL
        ? "rar-end-archive"
        : "sevenzip-next-header"
    } : {
      location: "overlay",
      discovery: "archive-scan",
      association: "unattributed",
      validation: finding.detectedType === EMBEDDED_RAR_LABEL
        ? "rar-end-archive"
        : "sevenzip-next-header"
    };

export const analyzePePayloads = async (
  file: File,
  reader: FileRangeReader,
  overlay: PeOverlayAnalysis | null | undefined,
  packers: PePackerAnalysis | null | undefined,
  resources?: PeResources | null
): Promise<PePayloadAnalysis | null> => {
  const entries = await findResourcePePayloads(reader, resources);
  const installers = nsisFindings(packers);
  for (const range of overlay?.ranges ?? []) {
    const findings = await findEmbeddedPayloadsInRangePrefix(
      file,
      reader,
      range,
      AUTOMATIC_PAYLOAD_SCAN_BYTES
    );
    for (const finding of findings) {
      const format = payloadFormat(finding);
      if (!format) continue;
      entries.push({
        end: finding.end,
        format,
        provenance: overlayPayloadProvenance(finding, installers),
        start: finding.start
      });
    }
  }
  return entries.length ? { entries } : null;
};

const explainedRanges = (
  packers: PePackerAnalysis | null | undefined,
  payloads: PePayloadAnalysis | null | undefined
): FileRange[] => [
  ...innoFindings(packers).map(finding => ({
    start: finding.dataOffset,
    end: finding.totalSize
  })),
  ...nsisFindings(packers).map(finding => ({
    start: finding.firstHeaderOffset,
    end: finding.firstHeaderOffset + finding.followingDataSize
  })),
  ...(payloads?.entries ?? []).map(payload => ({ start: payload.start, end: payload.end }))
];

const readCertificateAlignmentPadding = async (
  reader: FileRangeReader,
  certificateTableStart: number | null,
  ranges: FileRange[],
  explained: FileRange[]
): Promise<FileRange | null> => {
  if (certificateTableStart == null || certificateTableStart % 8 !== 0 ||
      certificateTableStart > reader.size) return null;
  const tail = ranges.find(range => range.end === certificateTableStart);
  if (!tail) return null;
  const paddingStartLimit = Math.max(tail.start, certificateTableStart - 7);
  const padding = await reader.read(paddingStartLimit, certificateTableStart - paddingStartLimit);
  if (padding.byteLength !== certificateTableStart - paddingStartLimit) return null;
  let paddingStart = certificateTableStart;
  while (paddingStart > paddingStartLimit && padding.getUint8(paddingStart - paddingStartLimit - 1) === 0) {
    paddingStart -= 1;
  }
  return explained.some(range => range.end === paddingStart)
    ? { start: paddingStart, end: certificateTableStart }
    : null;
};

export const subtractExplainedPeOverlay = async (
  reader: FileRangeReader,
  certificateTableStart: number | null,
  overlay: PeOverlayAnalysis | null | undefined,
  packers: PePackerAnalysis | null | undefined,
  payloads: PePayloadAnalysis | null | undefined
): Promise<PeOverlayAnalysis | null> => {
  if (!overlay) return null;
  const explained = explainedRanges(packers, payloads);
  const remaining = subtractFileRanges(overlay.ranges, explained);
  const padding = await readCertificateAlignmentPadding(
    reader,
    certificateTableStart,
    remaining,
    explained
  );
  const ranges = (padding ? subtractFileRanges(remaining, [padding]) : remaining)
    .map(range => ({ ...range, size: range.end - range.start, findings: [] }));
  const warnings = overlay.warnings?.length ? overlay.warnings : undefined;
  if (!ranges.length && !warnings) return null;
  return {
    ranges,
    ...(warnings ? { warnings } : {})
  };
};
