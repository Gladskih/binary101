"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderNativeAotCandidate } from "../../../../renderers/pe/native-aot.js";
import type { PeNativeAotCandidate } from "../../../../analyzers/pe/native-aot.js";

const generatedText = (index: number): string => `value-${index.toString(36)}`;

const makeCandidate = (): PeNativeAotCandidate => ({
  status: "candidate",
  evidence: [`<${generatedText(0)}>`],
  note: `&${generatedText(1)}`
});

void test("renderNativeAotCandidate renders nothing when evidence is absent", () => {
  const out: string[] = [];

  renderNativeAotCandidate(null, out);

  assert.deepStrictEqual(out, []);
});

void test("renderNativeAotCandidate renders escaped conservative evidence", () => {
  const out: string[] = [];

  renderNativeAotCandidate(makeCandidate(), out);

  const html = out.join("");
  assert.ok(html.includes("Native AOT candidate"));
  assert.ok(html.includes("&lt;value-0>"));
  assert.ok(html.includes("&value-1"));
});
