"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { createX86InstructionSetUsageTracker } from "../../../../analyzers/x86/instruction-set-usage.js";
import type { IcedX86Module } from "../../../../analyzers/x86/disassembly-iced.js";

void test("createX86InstructionSetUsageTracker reports known and unknown features", () => {
  const tracker = createX86InstructionSetUsageTracker(createCpuidFeatureTable());
  tracker.featureCounts.set(1, 2);
  tracker.featureCounts.set(99, 3);
  assert.deepEqual(tracker.knownFeatureCounts(), { SSE2: 2 });
  assert.deepEqual(
    tracker.instructionSets().map(entry => [entry.id, entry.instructionCount]),
    [["#99", 3], ["SSE2", 2]]
  );
});

const createCpuidFeatureTable = (): IcedX86Module["CpuidFeature"] => {
  return { SSE2: 1, AVX: 2, 1: "SSE2", 2: "AVX" } as unknown as
    IcedX86Module["CpuidFeature"];
};
