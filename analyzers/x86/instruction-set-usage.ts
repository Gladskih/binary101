"use strict";

import {
  KNOWN_CPUID_FEATURES,
  describeCpuidFeature,
  formatCpuidLabel
} from "./cpuid-features.js";
import type { IcedX86Module } from "./disassembly-iced.js";

export type X86InstructionSetUsage = {
  id: string;
  label: string;
  description: string;
  instructionCount: number;
};

export type X86InstructionSetUsageTracker = {
  featureCounts: Map<number, number>;
  knownFeatureCounts: () => Record<string, number>;
  instructionSets: () => X86InstructionSetUsage[];
};

export const createX86InstructionSetUsageTracker = (
  cpuidFeature: IcedX86Module["CpuidFeature"]
): X86InstructionSetUsageTracker => {
  const featureCounts = new Map<number, number>();
  const knownFeatures = KNOWN_CPUID_FEATURES
    .map(id => ({ id, value: cpuidFeature[id] }))
    .filter((entry): entry is { id: string; value: number } => typeof entry.value === "number");
  const knownFeatureCounts = (): Record<string, number> => {
    const out: Record<string, number> = {};
    for (const { id, value } of knownFeatures) {
      const count = featureCounts.get(value);
      if (count) out[id] = count;
    }
    return out;
  };
  const instructionSets = (): X86InstructionSetUsage[] =>
    [...featureCounts.entries()]
      .map(([feature, count]) => {
        const id = cpuidFeature[feature] ?? `#${feature}`;
        return {
          id,
          label: formatCpuidLabel(id),
          description: describeCpuidFeature(id),
          instructionCount: count
        };
      })
      .sort((a, b) => b.instructionCount - a.instructionCount || a.id.localeCompare(b.id));
  return { featureCounts, knownFeatureCounts, instructionSets };
};
