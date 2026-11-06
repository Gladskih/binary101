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
import type { ParsedSecurityDirectory } from "./security/index.js";
import { readPeCertificateAlignmentPadding } from "./certificate-padding.js";
import { analyzeFlashProjector, isValidatedProjectorMovie, type FlashProjector } from "./flash-projector.js";
import type { SwfParseResult } from "../swf/types.js";

export type PePayloadFormat = "pe" | "rar" | "sevenzip" | "swf";

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
  }
  | {
    location: "overlay";
    discovery: "projector-footer";
    association: "flash-projector";
    validation: "projector-footer";
  };

export type PeExtractedPayload = {
  end: number;
  start: number;
} & ({
  format: "swf";
  provenance: Extract<PePayloadProvenance, { discovery: "projector-footer" }>;
  swf: SwfParseResult;
} | {
  format: Exclude<PePayloadFormat, "swf">;
  provenance: Exclude<PePayloadProvenance, { discovery: "projector-footer" }>;
});

export interface PePayloadAnalysis {
  entries: PeExtractedPayload[];
  projectorCandidate?: FlashProjector;
}

const projectorPayload = (projector: FlashProjector): Extract<PeExtractedPayload, { format: "swf" }> => ({
  ...projector, format: "swf", provenance: { location: "overlay", discovery: "projector-footer",
    association: "flash-projector", validation: "projector-footer" }
});

export const resolveProjectorCandidate = (
  analysis: PePayloadAnalysis, swf: SwfParseResult
): PePayloadAnalysis => {
  const candidate = analysis.projectorCandidate;
  if (!candidate) return analysis;
  if (!isValidatedProjectorMovie(swf)) return {
    ...analysis, projectorCandidate: { ...candidate, swf }
  };
  return { entries: [...analysis.entries, projectorPayload({ ...candidate, swf })] };
};

// Real installer inventory placed every validated 7z/RAR start within 180 KiB of its
// overlay start. One MiB preserves a wide margin while bounding automatic reads.
// This existing archive-only policy is independent of uncapped Projector/SWF inspection.
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

const payloadFormat = (finding: PeOverlayFinding): "rar" | "sevenzip" | null => {
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
): Extract<PePayloadProvenance, { discovery: "archive-scan" }> =>
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

const inspectProjectorPayload = async (
  file: File, overlay: PeOverlayAnalysis | null | undefined
): Promise<PePayloadAnalysis> => {
  const firstRange = overlay?.ranges[0];
  const projector = firstRange ? await analyzeFlashProjector(file, firstRange.start) : null;
  if (!projector) return { entries: [] };
  return isValidatedProjectorMovie(projector.swf)
    ? { entries: [projectorPayload(projector)] } : { entries: [], projectorCandidate: projector };
};

const findOverlayArchives = async (
  file: File, reader: FileRangeReader, ranges: FileRange[], installers: PeNsisPackerFinding[]
): Promise<PeExtractedPayload[]> => {
  const entries: PeExtractedPayload[] = [];
  for (const range of ranges) {
    const findings = await findEmbeddedPayloadsInRangePrefix(file, reader,
      { ...range, size: range.end - range.start, findings: [] }, AUTOMATIC_PAYLOAD_SCAN_BYTES);
    for (const finding of findings) {
      const format = payloadFormat(finding);
      if (!format) continue;
      entries.push({ end: finding.end, format,
        provenance: overlayPayloadProvenance(finding, installers), start: finding.start });
    }
  }
  return entries;
};

export const analyzePePayloads = async (
  file: File, reader: FileRangeReader, overlay: PeOverlayAnalysis | null | undefined,
  packers: PePackerAnalysis | null | undefined, resources?: PeResources | null
): Promise<PePayloadAnalysis | null> => {
  const projector = await inspectProjectorPayload(file, overlay);
  // A confirmed SWF is already explained. Avoid scanning its media bytes again as archive data.
  const ranges = subtractFileRanges(overlay?.ranges ?? [],
    projector.entries.map(payload => ({ start: payload.start, end: payload.end + 8 })));
  const entries = (await findResourcePePayloads(reader, resources)).concat(projector.entries,
    await findOverlayArchives(file, reader, ranges, nsisFindings(packers)));
  return entries.length || projector.projectorCandidate ? { ...projector, entries } : null;
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
  ...(payloads?.entries ?? []).map(payload => ({
    start: payload.start,
    // The verified Projector footer immediately follows the SWF.
    end: payload.end + (payload.format === "swf" ? 8 : 0)
  }))
];

export const subtractExplainedPeOverlay = async (
  reader: FileRangeReader,
  security: ParsedSecurityDirectory | null | undefined,
  overlay: PeOverlayAnalysis | null | undefined,
  packers: PePackerAnalysis | null | undefined,
  payloads: PePayloadAnalysis | null | undefined
): Promise<PeOverlayAnalysis | null> => {
  if (!overlay) return null;
  const explained = explainedRanges(packers, payloads);
  const remaining = subtractFileRanges(overlay.ranges, explained);
  const padding = await readPeCertificateAlignmentPadding(
    reader,
    security,
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
