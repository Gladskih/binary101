"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PePayloadAnalysis } from "../../../../analyzers/pe/payloads.js";
import {
  getStandalonePePayloads,
  getPePayloadSectionDescriptor,
  getResourcePayloadSectionDescriptor,
  renderPePayloadEntries,
  renderPePayloads
} from "../../../../renderers/pe/payloads.js";
import { renderPeProjectorStatus } from "../../../../renderers/pe/payloads.js";

const projectorAnalysis = (): PePayloadAnalysis => ({ entries: [{ start: 128, end: 256,
  format: "swf", provenance: { location: "overlay", discovery: "projector-footer",
    association: "flash-projector", validation: "projector-footer" },
  swf: { signature: "FWS", version: 9, fileLength: 128, tags: [], issues: [] } }] });

void test("renderPePayloads presents Projector metadata and exact SWF download as a payload, not an archive", () => {
  const out: string[] = [];
  const analysis = projectorAnalysis();

  renderPePayloads(analysis, "appended", out);

  const html = out.join("");
  assert.deepEqual(getPePayloadSectionDescriptor(analysis), { title: "Appended payload", summary: "1 payload" });
  assert.match(html, /Flash Projector SWF/);
  assert.match(html, /Flash SWF/);
  assert.match(html, /data-payload-format="swf"/);
  assert.match(html, /data-payload-start="128"/);
  assert.match(html, /data-payload-end="256"/);
  assert.match(html, /EOF Projector marker/);
  assert.match(html, /SWF movie header checked/);
  assert.ok(!html.includes("Appended archive"));
});

void test("mixed appended formats keep a payload summary", () => {
  const mixed = { entries: [...projectorAnalysis().entries, ...analysis.entries] };

  assert.deepEqual(getPePayloadSectionDescriptor(mixed), { title: "Appended payloads", summary: "2 payloads" });
});

void test("unverified Projector candidates show progress or infrastructure failure without claiming a found payload", () => {
  const candidate = { start: 128, end: 200,
    swf: { signature: "CWS" as const, version: 9, fileLength: 31, issues: [] } };
  const pending = { entries: [], projectorCandidate: candidate };
  const rejected = { entries: [], projectorCandidate: { ...candidate, swf: { ...candidate.swf, issues: ["bad body"] } } };

  assert.equal(getPePayloadSectionDescriptor(pending), null);
  assert.match(renderPeProjectorStatus(pending), /analysis is running/);
  assert.match(renderPeProjectorStatus({ entries: [], projectorCandidate: {
    ...candidate, bodyReadError: "<worker unavailable>" } }), /&lt;worker unavailable/);
  assert.equal(renderPeProjectorStatus(rejected), "");
  assert.equal(renderPeProjectorStatus(null), "");
});

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
