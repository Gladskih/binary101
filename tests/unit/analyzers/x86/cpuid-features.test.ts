"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { CpuidFeature } from "iced-x86";
import { describeCpuidFeature } from "../../../../analyzers/x86/cpuid-features.js";

void test("describeCpuidFeature explains every CpuidFeature exported by iced-x86", () => {
  const featureNames = Object.entries(CpuidFeature)
    .filter(([, value]) => typeof value === "number")
    .map(([name]) => name);

  for (const name of featureNames) {
    assert.notEqual(
      describeCpuidFeature(name),
      "No description is available for this instruction requirement."
    );
  }
});

void test("describeCpuidFeature returns a fallback for an unknown identifier", () => {
  assert.equal(
    describeCpuidFeature("FUTURE_EXTENSION"),
    "No description is available for this instruction requirement."
  );
});
