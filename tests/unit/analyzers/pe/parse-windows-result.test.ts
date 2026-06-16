"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { buildPeDebugSection } from "../../../../analyzers/pe/parse-windows-result.js";
import type { PeDebugArtifacts } from "../../../../analyzers/pe/parse-windows.js";

void test("buildPeDebugSection returns null for empty debug artifacts", () => {
  assert.equal(buildPeDebugSection(createDebugArtifacts()), null);
});

void test("buildPeDebugSection keeps entries, notes, ranges, and warnings visible", () => {
  const section = buildPeDebugSection(createDebugArtifacts({
    debugResult: {
      entry: null,
      entries: [],
      rawDataRanges: [{ start: 1, end: 2 }],
      warning: null
    } as PeDebugArtifacts["debugResult"],
    debugNotes: ["note"],
    debugWarning: "warning"
  }));
  assert.equal(section?.entry, null);
  assert.deepEqual(section?.notes, ["note"]);
  assert.deepEqual(section?.rawDataRanges, [{ start: 1, end: 2 }]);
  assert.equal(section?.warning, "warning");
});

const createDebugArtifacts = (
  overrides: Partial<PeDebugArtifacts> = {}
): PeDebugArtifacts => ({
  debugResult: {
    entry: null,
    entries: [],
    rawDataRanges: [],
    warning: null
  } as PeDebugArtifacts["debugResult"],
  coffDebug: null,
  debugNotes: undefined,
  debugWarning: null,
  ...overrides
});
