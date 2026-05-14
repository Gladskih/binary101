"use strict";

import { detectBunStandalone } from "./bun-standalone.js";
import { detectNsisInstaller } from "./nsis-installer.js";
import type {
  PePackerAnalysis,
  PePackerAnalysisInput,
  PePackerDetectorResult
} from "./types.js";

type PePackerAnalyzer = (input: PePackerAnalysisInput) => Promise<PePackerDetectorResult>;

const DETECTORS: readonly PePackerAnalyzer[] = [
  input => detectBunStandalone({
    reader: input.reader,
    sections: input.sections,
    imagePointerBytes: input.imagePointerBytes
  }),
  input => detectNsisInstaller(input.overlay == null
    ? { reader: input.reader }
    : { reader: input.reader, overlay: input.overlay })
];

export const analyzePePackers = async (
  input: PePackerAnalysisInput
): Promise<PePackerAnalysis | null> => {
  const findings: PePackerAnalysis["findings"] = [];
  const warnings: string[] = [];
  for (const detector of DETECTORS) {
    const result = await detector(input);
    findings.push(...result.findings);
    warnings.push(...result.warnings);
  }
  if (!findings.length && !warnings.length) return null;
  return {
    findings,
    ...(warnings.length ? { warnings: [...new Set(warnings)] } : {})
  };
};

export type {
  BunStandaloneDetectorInput,
  NsisInstallerDetectorInput,
  PePackerAnalysis,
  PePackerConfidence,
  PePackerDetail,
  PePackerFinding,
  PePackerKind
} from "./types.js";
