"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  getStandalonePePayloads,
  getPePayloadSectionDescriptor,
  getResourcePayloadSectionDescriptor,
  renderPePayloadEntries,
  renderPePayloads
} from "../../../../renderers/pe/payloads.js";

const analysis = {
  entries: [
    {
      start: 0x100,
      end: 0x200,
      format: "sevenzip" as const,
      provenance: {
        location: "overlay" as const,
        discovery: "archive-scan" as const,
        association: "nsis-installer-data" as const,
        validation: "sevenzip-next-header" as const
      }
    },
    {
      start: 0x300,
      end: 0x500,
      format: "rar" as const,
      provenance: {
        location: "overlay" as const,
        discovery: "archive-scan" as const,
        association: "unattributed" as const,
        validation: "rar-end-archive" as const
      }
    }
  ]
};

const resourceAnalysis = {
  entries: [{
    start: 0x100,
    end: 0x300,
    format: "pe" as const,
    provenance: {
      location: "resource" as const,
      discovery: "resource-leaf" as const,
      resourcePath: [{ id: 10, name: null }, { id: 101, name: null }, { id: 1033, name: null }],
      validation: "pe-signatures" as const
    }
  }]
};

void test("renderPePayloadEntries renders exact archive bounds and download metadata", () => {
  const html = renderPePayloadEntries(analysis.entries, "Archive");

  assert.ok(html.includes("<caption>Archive</caption>"));
  assert.ok(html.includes("<b>7z archive</b>"));
  assert.ok(html.includes("0x00000100-0x00000200"));
  assert.ok(html.includes(`data-payload-format="sevenzip"`));
  assert.ok(html.includes(`data-payload-start="256"`));
  assert.ok(html.includes(`data-payload-end="512"`));
  assert.ok(html.includes("RAR archive"));
});

void test("renderPePayloadEntries states limited PE resource validation", () => {
  const html = renderPePayloadEntries(resourceAnalysis.entries);

  assert.ok(html.includes("PE-signature resource object"));
  assert.ok(html.includes("MZ, bounded e_lfanew, and PE signature"));
  assert.ok(html.includes(`data-payload-format="pe"`));
});

void test("getStandalonePePayloads excludes archives owned by NSIS", () => {
  assert.deepEqual(getStandalonePePayloads(analysis), [analysis.entries[1]]);
  assert.deepEqual(getStandalonePePayloads(null), []);
});

void test("getPePayloadSectionDescriptor summarizes appended archives", () => {
  assert.deepEqual(getPePayloadSectionDescriptor(analysis), {
    summary: "1 archive",
    title: "Appended archive"
  });
  assert.equal(getPePayloadSectionDescriptor(null), null);
});

void test("getResourcePayloadSectionDescriptor identifies PE-signature resource objects", () => {
  assert.deepEqual(getResourcePayloadSectionDescriptor(resourceAnalysis), {
    summary: "1 PE-signature object",
    title: "PE-signature resource objects"
  });
  assert.equal(getResourcePayloadSectionDescriptor(null), null);
});

void test("renderPePayloads renders only standalone payloads in a dedicated section", () => {
  const out: string[] = [];

  renderPePayloads(analysis, "appended", out);

  const html = out.join("");
  assert.ok(html.includes("Appended archive"));
  assert.ok(html.includes("No recognized installer or packer owns this range."));
  assert.ok(html.includes("RAR archive"));
  assert.ok(!html.includes("7z archive"));
});

void test("renderPePayloads omits an empty section", () => {
  const out: string[] = [];

  renderPePayloads(null, "appended", out);

  assert.deepEqual(out, []);
});

void test("renderPePayloads keeps PE-signature resource objects separate", () => {
  const out: string[] = [];

  renderPePayloads(resourceAnalysis, "resource", out);

  assert.ok(out.join("").includes("PE-signature resource objects"));
});
