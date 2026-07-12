"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { PeOverlayAnalysis, PeOverlayFinding } from "./overlay.js";
import { findEmbeddedPayloadsInRangePrefix } from "./overlay-scan.js";
import {
  EMBEDDED_RAR_LABEL,
  EMBEDDED_SEVEN_ZIP_LABEL
} from "./overlay-embedded.js";
import type { PePackerAnalysis, PeNsisPackerFinding } from "./packers/index.js";
import { subtractFileRanges, type FileRange } from "./layout/file-ranges.js";

export type PePayloadFormat = "rar" | "sevenzip";
export type PePayloadSource = "nsis" | "overlay";

export interface PeExtractedPayload {
  end: number;
  format: PePayloadFormat;
  source: PePayloadSource;
  start: number;
}

export interface PePayloadAnalysis {
  entries: PeExtractedPayload[];
}

// Real installer inventory placed every validated 7z/RAR start within 180 KiB of its
// overlay start. One MiB preserves a wide margin while bounding automatic reads.
const AUTOMATIC_PAYLOAD_SCAN_BYTES = 1024 * 1024;

const payloadFormat = (finding: PeOverlayFinding): PePayloadFormat | null => {
  if (finding.detectedType === EMBEDDED_SEVEN_ZIP_LABEL) return "sevenzip";
  if (finding.detectedType === EMBEDDED_RAR_LABEL) return "rar";
  return null;
};

const nsisFindings = (packers: PePackerAnalysis | null | undefined): PeNsisPackerFinding[] =>
  packers?.reports
    .find(report => report.id === "nsis-installer")
    ?.findings.filter(finding => finding.id === "nsis-installer") ?? [];

const payloadSource = (
  finding: PeOverlayFinding,
  installers: PeNsisPackerFinding[]
): PePayloadSource =>
  installers.some(installer =>
    finding.start >= installer.firstHeaderOffset &&
    finding.end <= installer.firstHeaderOffset + installer.followingDataSize
  ) ? "nsis" : "overlay";

export const analyzePePayloads = async (
  file: File,
  reader: FileRangeReader,
  overlay: PeOverlayAnalysis | null | undefined,
  packers: PePackerAnalysis | null | undefined
): Promise<PePayloadAnalysis | null> => {
  const entries: PeExtractedPayload[] = [];
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
        source: payloadSource(finding, installers),
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
  ...nsisFindings(packers).map(finding => ({
    start: finding.firstHeaderOffset,
    end: finding.firstHeaderOffset + finding.followingDataSize
  })),
  ...(payloads?.entries ?? []).map(payload => ({ start: payload.start, end: payload.end }))
];

export const subtractExplainedPeOverlay = (
  overlay: PeOverlayAnalysis | null | undefined,
  packers: PePackerAnalysis | null | undefined,
  payloads: PePayloadAnalysis | null | undefined
): PeOverlayAnalysis | null => {
  if (!overlay) return null;
  const ranges = subtractFileRanges(overlay.ranges, explainedRanges(packers, payloads))
    .map(range => ({ ...range, size: range.end - range.start, findings: [] }));
  const warnings = overlay.warnings?.length ? overlay.warnings : undefined;
  if (!ranges.length && !warnings) return null;
  return {
    ranges,
    ...(warnings ? { warnings } : {})
  };
};
