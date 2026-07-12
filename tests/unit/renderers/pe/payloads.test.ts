"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  getStandalonePePayloads,
  getPePayloadSectionDescriptor,
  renderPePayloadEntries,
  renderPePayloads
} from "../../../../renderers/pe/payloads.js";

const analysis = {
  entries: [
    { start: 0x100, end: 0x200, format: "sevenzip" as const, source: "nsis" as const },
    { start: 0x300, end: 0x500, format: "rar" as const, source: "overlay" as const }
  ]
};

void test("renderPePayloadEntries renders exact archive bounds and download metadata", () => {
  const html = renderPePayloadEntries(analysis.entries, "Archive");

  assert.ok(html.includes("Archive</b> - 7z archive"));
  assert.ok(html.includes("0x00000100-0x00000200"));
  assert.ok(html.includes(`data-payload-format="sevenzip"`));
  assert.ok(html.includes(`data-payload-start="256"`));
  assert.ok(html.includes(`data-payload-end="512"`));
  assert.ok(html.includes("RAR archive"));
});

void test("getStandalonePePayloads excludes archives owned by NSIS", () => {
  assert.deepEqual(getStandalonePePayloads(analysis), [analysis.entries[1]]);
  assert.deepEqual(getStandalonePePayloads(null), []);
});

void test("getPePayloadSectionDescriptor summarizes standalone archives", () => {
  assert.deepEqual(getPePayloadSectionDescriptor(analysis), {
    key: "payloads",
    summary: "1 validated archive(s)",
    title: "Embedded payloads"
  });
  assert.equal(getPePayloadSectionDescriptor(null), null);
});

void test("renderPePayloads renders only standalone payloads in a dedicated section", () => {
  const out: string[] = [];

  renderPePayloads(analysis, out);

  const html = out.join("");
  assert.ok(html.includes("Embedded payloads"));
  assert.ok(html.includes("1 validated archive"));
  assert.ok(html.includes("RAR archive"));
  assert.ok(!html.includes("7z archive"));
});

void test("renderPePayloads omits an empty section", () => {
  const out: string[] = [];

  renderPePayloads(null, out);

  assert.deepEqual(out, []);
});
