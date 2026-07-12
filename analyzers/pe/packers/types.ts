"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeOverlayAnalysis } from "../overlay.js";
import type { PeSection } from "../types.js";
import type { UpxPackHeader } from "./upx-pack-header.js";

export type PePackerKind = "executable-packer" | "installer" | "runtime-packager";
export type PePackerConfidence = "high";
export type PePackerId = "bun-standalone" | "nsis-installer" | "upx";
export type BunPayloadStorage = "length-prefixed" | "section-virtual-data";

interface PePackerFindingBase {
  name: string;
  kind: PePackerKind;
  confidence: PePackerConfidence;
  evidence: string[];
}

export interface PeNsisPackerFinding extends PePackerFindingBase {
  id: "nsis-installer";
  headerSize: number;
  firstHeaderOffset: number;
  flags: number;
  followingDataSize: number;
}

export interface BunOffsetMetadata {
  byteCount: number;
  compileArgvBytes: number;
  entryPointId: number;
  flags: number;
  moduleListBytes: number;
}

export interface PeBunPackerFinding extends PePackerFindingBase {
  id: "bun-standalone";
  offsetMetadata?: BunOffsetMetadata;
  payloadSize: number;
  payloadStart: number;
  sectionSize: number;
  sectionStart: number;
  storage: BunPayloadStorage;
}

export interface PeUpxPackerFinding extends PePackerFindingBase {
  id: "upx";
  packedFileSize: number;
  packHeader: UpxPackHeader;
  packHeaderOffset: number;
}

export type PePackerFinding =
  | PeBunPackerFinding
  | PeNsisPackerFinding
  | PeUpxPackerFinding;

export interface PePackerReport {
  id: PePackerId;
  findings: PePackerFinding[];
  warnings: string[];
}

export interface PePackerAnalysis {
  reports: PePackerReport[];
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

export interface UpxDetectorInput {
  reader: FileRangeReader;
  sections: PeSection[];
  imagePointerBytes: 4 | 8;
}

export interface PePackerDetectorResult<
  TFinding extends PePackerFinding = PePackerFinding
> {
  findings: TFinding[];
  warnings: string[];
}

export type PePackerDetector<TInput> = (input: TInput) => Promise<PePackerDetectorResult>;
