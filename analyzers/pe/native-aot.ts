"use strict";

import type { PeSection } from "./types.js";
import { peSectionNameValue } from "./sections/name.js";

export interface PeNativeAotCandidate {
  status: "candidate";
  evidence: string[];
  note: string;
}

export const detectNativeAotCandidate = (
  clrPresent: boolean,
  exportsInfo: { entries: Array<{ name: string | null }> } | null,
  sections: PeSection[]
): PeNativeAotCandidate | null => {
  const evidence: string[] = [];
  if (exportsInfo?.entries.some(entry => entry.name === "DotNetRuntimeDebugHeader")) {
    evidence.push("Export named DotNetRuntimeDebugHeader is present.");
  }
  const sectionNames = new Set(sections.map(section => peSectionNameValue(section.name)));
  if (!clrPresent && sectionNames.has(".managed") && sectionNames.has(".hydrated")) {
    evidence.push("No CLR directory is present and both .managed and .hydrated sections exist.");
  }
  return evidence.length
    ? {
        status: "candidate",
        evidence,
        note: "Native AOT can look like a normal native PE; this is conservative local evidence, not a guarantee."
      }
    : null;
};
