"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  SECTION_ENTROPY_TOOLTIP,
  formatSectionEntropy,
  renderSectionEntropyControl,
  renderSectionEntropyValue,
  sectionEntropySortValue,
  sectionEntropySummary
} from "../../../renderers/section-entropy.js";

void test("section entropy rendering distinguishes pending, unavailable, and calculated values", () => {
  assert.match(SECTION_ENTROPY_TOOLTIP, /entropy alone is not a packer verdict/);
  assert.equal(formatSectionEntropy(undefined), "Not calculated");
  assert.equal(formatSectionEntropy(null), "Unavailable");
  assert.equal(formatSectionEntropy(Number.NaN), "Unavailable");
  assert.equal(formatSectionEntropy(7.125), "7.13");
  assert.equal(sectionEntropySortValue(undefined), "");
  assert.equal(sectionEntropySortValue(null), "");
  assert.equal(sectionEntropySortValue(Number.NaN), "");
  assert.equal(sectionEntropySortValue(7.125), "7.125");
  assert.match(renderSectionEntropyValue(undefined, 3), /data-section-entropy-index="3"/);
  assert.match(renderSectionEntropyValue(null, 3), /class="dim">Unavailable/);
  assert.equal(
    renderSectionEntropyValue(7.125, 3),
    `<span data-section-entropy-index="3">7.13</span>`
  );
});

void test("section entropy control summarizes all-section calculation state", () => {
  const pending = renderSectionEntropyControl([{}, {}]);
  const partial = renderSectionEntropyControl([{ entropy: 0 }, {}]);
  const calculated = renderSectionEntropyControl([{ entropy: 0 }, { entropy: null }]);

  assert.match(pending, /Calculate entropy for all sections/);
  assert.match(pending, /^<div/);
  assert.match(pending, /on demand/);
  assert.match(partial, /Calculate entropy for all sections/);
  assert.match(calculated, /Recalculate entropy for all sections/);
  assert.match(calculated, /Calculated for 1 of 2 sections; 1 raw range unavailable/);
  assert.equal(
    sectionEntropySummary([{ entropy: 0 }, { entropy: null }, { entropy: null }]),
    "Calculated for 1 of 3 sections; 2 raw ranges unavailable."
  );
});
