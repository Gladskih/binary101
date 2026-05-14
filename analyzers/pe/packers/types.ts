"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeOverlayAnalysis } from "../overlay.js";
import type { PeSection } from "../types.js";

export type PePackerKind = "installer" | "runtime-packager";
export type PePackerConfidence = "high";

export type PePackerDetail =
  | { label: string; kind: "bytes"; value: number }
  | { label: string; kind: "number"; value: number }
  | { label: string; kind: "offset"; value: number }
  | { label: string; kind: "range"; start: number; end: number }
  | { label: string; kind: "text"; value: string };

export interface PePackerFinding {
  id: string;
  name: string;
  kind: PePackerKind;
  confidence: PePackerConfidence;
  evidence: string[];
  details?: PePackerDetail[];
}

export interface PePackerAnalysis {
  findings: PePackerFinding[];
  warnings?: string[];
}

export interface PePackerAnalysisInput {
  reader: FileRangeReader;
  sections: PeSection[];
  overlay?: PeOverlayAnalysis | null;
  imagePointerBytes: 4 | 8;
}

export interface BunStandaloneDetectorInput {
  reader: FileRangeReader;
  sections: PeSection[];
  imagePointerBytes: 4 | 8;
}

export interface NsisInstallerDetectorInput {
  reader: FileRangeReader;
  overlay?: PeOverlayAnalysis | null;
}

export interface PePackerDetectorResult {
  findings: PePackerFinding[];
  warnings: string[];
}

export type PePackerDetector<TInput> = (input: TInput) => Promise<PePackerDetectorResult>;
