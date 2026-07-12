"use strict";

import { detectBunStandalone } from "./bun-standalone.js";
import { detectNsisInstaller } from "./nsis-installer.js";
import { detectInnoSetup } from "./inno-setup.js";
import { detectUpx } from "./upx.js";
import type {
  PePackerAnalysis,
  PePackerAnalysisInput,
  PePackerDetectorResult,
  PePackerId
} from "./types.js";

type PePackerAnalyzer = (input: PePackerAnalysisInput) => Promise<PePackerDetectorResult>;
type PePackerAnalyzerRegistration = { id: PePackerId; analyze: PePackerAnalyzer };

const DETECTORS: readonly PePackerAnalyzerRegistration[] = [{
  id: "upx",
  analyze: input => detectUpx({
    reader: input.reader,
    sections: input.sections,
    imagePointerBytes: input.imagePointerBytes
  })
}, {
  id: "inno-setup",
  analyze: input => detectInnoSetup(input.resources == null
    ? { reader: input.reader }
    : { reader: input.reader, resources: input.resources })
}, {
  id: "bun-standalone",
  analyze: input => detectBunStandalone({
    reader: input.reader,
    sections: input.sections,
    imagePointerBytes: input.imagePointerBytes
  })
}, {
  id: "nsis-installer",
  analyze: input => detectNsisInstaller(input.overlay == null
    ? { reader: input.reader }
    : { reader: input.reader, overlay: input.overlay })
}];

export const analyzePePackers = async (
  input: PePackerAnalysisInput
): Promise<PePackerAnalysis | null> => {
  const reports: PePackerAnalysis["reports"] = [];
  for (const detector of DETECTORS) {
    const result = await detector.analyze(input);
    if (result.findings.length || result.warnings.length) {
      reports.push({
        id: detector.id,
        findings: result.findings,
        warnings: [...new Set(result.warnings)]
      });
    }
  }
  return reports.length ? { reports } : null;
};

export type {
  BunOffsetMetadata,
  BunPayloadStorage,
  BunStandaloneDetectorInput,
  InnoSetupDetectorInput,
  NsisInstallerDetectorInput,
  PeBunPackerFinding,
  PeInnoSetupFinding,
  PePackerAnalysis,
  PePackerConfidence,
  PePackerFinding,
  PePackerId,
  PePackerKind,
  PeNsisPackerFinding,
  PePackerReport,
  PeUpxPackerFinding,
  UpxDetectorInput
} from "./types.js";
