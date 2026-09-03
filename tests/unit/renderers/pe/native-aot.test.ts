"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderNativeAotCandidate } from "../../../../renderers/pe/native-aot.js";
import type { PeNativeAotCandidate } from "../../../../analyzers/pe/native-aot.js";
import type { PeNativeAotMetadata } from "../../../../analyzers/pe/native-aot/format.js";

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

void test("renderNativeAotCandidate renders confirmed metadata as a table", () => {
  const metadata: PeNativeAotMetadata = {
    status: "confirmed",
    layout: "nativeaot-readytorun-pointer-range-v1",
    modulePointerRva: 0x1080,
    headerRva: 0x1100,
    majorVersion: 16,
    minorVersion: 0,
    sections: [{
      type: 313,
      rva: 0x1400,
      size: 32
    }, {
      type: 325,
      rva: 0x1500,
      size: null
    }]
  };
  const out: string[] = [];

  renderNativeAotCandidate(metadata, out);

  const html = out.join("");
  assert.ok(html.includes("NativeAOT metadata"));
  assert.ok(html.includes("turns managed code into native machine code"));
  assert.ok(html.includes("names alone are not accepted as evidence"));
  assert.ok(html.includes("nativeaot-readytorun-pointer-range-v1"));
  assert.ok(html.includes("ReadyToRun header format version"));
  assert.ok(html.includes("Embedded reflection metadata"));
  assert.ok(html.includes("one address rather than a byte range"));
  assert.ok(html.includes("0x00001400"));
  assert.ok(html.includes('class="table peNativeAotSectionsTable"'));
  assert.ok(html.includes('class="peNativeAotTable__compact peNumeric">-</td>'));
});
