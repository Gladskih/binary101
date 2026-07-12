"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  PeBunPackerFinding,
  PeDetailedPackerFinding,
  PePackerReport,
  PeUpxPackerFinding
} from "../../../../analyzers/pe/packers/types.js";
import { renderPackerReport } from "../../../../renderers/pe/packers.js";

const createBunFinding = (): PeBunPackerFinding => ({
  id: "bun-standalone",
  name: "Bun standalone executable",
  kind: "runtime-packager",
  confidence: "high",
  evidence: ["<evidence>", "second check"],
  sectionStart: 0x10,
  sectionSize: 0x40,
  payloadStart: 0x18,
  payloadSize: 0x20,
  storage: "length-prefixed"
});

const createNsisFinding = (): PeDetailedPackerFinding => ({
  id: "nsis-installer",
  name: "NSIS installer",
  kind: "installer",
  confidence: "high",
  evidence: ["NSIS verified"],
  details: [{ label: "Following data length", kind: "bytes", value: 16 }]
});

const createBunReport = (): PePackerReport => ({
  id: "bun-standalone",
  findings: [createBunFinding()],
  warnings: ["<warning>"]
});

const createUpxFinding = (): PeUpxPackerFinding => ({
  id: "upx",
  name: "UPX executable packer",
  kind: "executable-packer",
  confidence: "high",
  evidence: ["UPX verified"],
  packedFileSize: 768,
  packHeaderOffset: 0x100,
  packHeader: {
    version: 13,
    format: 36,
    method: 14,
    level: 9,
    unpackedAdler32: 1,
    packedAdler32: 2,
    unpackedSize: 2048,
    packedSize: 512,
    originalFileSize: 1024,
    filter: 0,
    filterParameter: 0,
    filterMru: 0,
    headerSize: 32,
    headerChecksum: 3
  }
});

void test("renderPackerReport renders nothing when a report is absent", () => {
  const out: string[] = [];

  renderPackerReport(null, out);

  assert.deepEqual(out, []);
});

void test("renderPackerReport renders one dedicated Bun section", () => {
  const out: string[] = [];

  renderPackerReport(createBunReport(), out);

  const html = out.join("");
  assert.ok(html.includes(`<b>Bun standalone executable</b> - verified, 1 warning`));
  assert.doesNotMatch(html, /Packaging analysis|runtime packager|<article|<header/);
  assert.ok(html.includes("&lt;evidence>"));
  assert.ok(html.includes("&lt;warning>"));
  assert.doesNotMatch(html, /Finding 1:/);
  assert.ok(html.includes(
    `<div class="pePackerFinding">` +
    `<div class="smallNote pePackerFinding__evidenceLabel">Validation checks</div>`
  ));
  assert.ok(html.includes(
    `<ul class="smallNote manifestCheckList pePackerFinding__evidence">` +
    `<li class="manifestCheckItem manifestCheckItem--pass">` +
    `<span class="manifestCheckIcon">&#10003;</span><span>&lt;evidence></span></li>`
  ));
  assert.ok(html.includes(
    `</li><li class="manifestCheckItem manifestCheckItem--pass">` +
    `<span class="manifestCheckIcon">&#10003;</span><span>second check</span></li></ul>`
  ));
  assert.ok(html.includes(
    `<div class="tableWrap"><table class="table peBunTable pePackerFinding__details">`
  ));
  assert.match(html, /<th>Field<\/th><th>Value<\/th><th>Meaning<\/th>/);
  assert.ok(html.includes(
    `<tr><th scope="row" class="peBunTable__field">.bun raw start</th>` +
    `<td class="peNumeric">0x00000010</td>` +
    `<td class="smallNote pePackerFinding__meaning">` +
    `First raw file byte occupied by the .bun section.</td></tr>`
  ));
  assert.ok(html.includes("Length-prefixed PE section"));
  assert.ok(html.includes(`</tbody></table></div></div></div></details></section>`));
});

void test("renderPackerReport renders warning-only reports under their analyzer", () => {
  const out: string[] = [];

  renderPackerReport({ id: "nsis-installer", findings: [], warnings: ["bad"] }, out);

  const html = out.join("");
  assert.ok(html.includes(`<b>NSIS installer</b> - 1 warning`));
  assert.ok(html.includes("NSIS installer warnings"));
  assert.ok(html.includes("No verified finding was produced."));
});

void test("renderPackerReport routes UPX findings to the UPX-specific table", () => {
  const out: string[] = [];

  renderPackerReport({ id: "upx", findings: [createUpxFinding()], warnings: [] }, out);

  const html = out.join("");
  assert.ok(html.includes(`<b>UPX executable packer</b> - verified`));
  assert.ok(html.includes("File compression ratio"));
  assert.ok(html.includes("LZMA"));
  assert.doesNotMatch(html, /executable packer<\/span>/);
});

void test("renderPackerReport labels multiple findings without duplicating a single finding", () => {
  const report = createBunReport();
  report.warnings = [];
  report.findings.push({ ...createBunFinding(), evidence: ["other"] });
  const out: string[] = [];

  renderPackerReport(report, out);

  const html = out.join("");
  assert.ok(html.includes(
    `<h4 class="pePackerFinding__title">Finding 1: Bun standalone executable</h4>`
  ));
  assert.ok(html.includes(
    `</tbody></table></div></div><div class="pePackerFinding">` +
    `<h4 class="pePackerFinding__title">Finding 2: Bun standalone executable</h4>`
  ));
});

void test("renderPackerReport gives future generic details a visible meaning", () => {
  const finding = createNsisFinding();
  finding.details = [{ label: "Future field", kind: "number", value: 7 }];
  const report: PePackerReport = {
    id: "nsis-installer",
    findings: [finding],
    warnings: []
  };
  const out: string[] = [];

  renderPackerReport(report, out);

  assert.ok(out.join("").includes("Additional analyzer-specific metadata."));
});

void test("renderPackerReport formats every generic detail value kind", () => {
  const finding = createNsisFinding();
  finding.details = [
    { label: "Module-list bytes", kind: "bytes", value: 2048 },
    { label: "firstheader offset", kind: "offset", value: 29 },
    { label: "Flags", kind: "text", value: "silent" },
    { label: "Installer data range", kind: "range", start: 0x10, end: 0x20 }
  ];
  const report: PePackerReport = {
    id: "nsis-installer",
    findings: [finding],
    warnings: []
  };
  const out: string[] = [];

  renderPackerReport(report, out);

  const html = out.join("");
  assert.ok(html.includes(`<td class="peNumeric">2 KB (2048 bytes)</td>`));
  assert.ok(html.includes(`<td class="peNumeric">0x0000001d</td>`));
  assert.ok(html.includes(`<td>silent</td>`));
  assert.ok(html.includes(`0x00000010-0x00000020 (16 B (16 bytes))`));
  assert.ok(html.includes(`</tr><tr>`));
});
