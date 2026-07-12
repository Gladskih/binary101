"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PePackerReport } from "../../../../analyzers/pe/packers/index.js";
import {
  PE_PACKER_SECTIONS,
  pePackerReportSummary,
  pePackerSectionDescriptors
} from "../../../../renderers/pe/packer-sections.js";

const report = (findings: number, warnings: number): PePackerReport => ({
  id: "upx",
  findings: Array.from({ length: findings }, () => ({
    id: "upx",
    name: "UPX executable packer",
    kind: "executable-packer",
    confidence: "high",
    evidence: [],
    packedFileSize: 1,
    packHeaderOffset: 0,
    packHeader: {
      version: 13,
      format: 9,
      method: 2,
      level: 1,
      unpackedAdler32: 0,
      packedAdler32: 0,
      unpackedSize: 2,
      packedSize: 1,
      originalFileSize: 2,
      filter: 0,
      filterParameter: 0,
      filterMru: 0,
      headerSize: 32,
      headerChecksum: 0
    }
  })),
  warnings: Array.from({ length: warnings }, () => "warning")
});

void test("PE_PACKER_SECTIONS names every analyzer-specific section", () => {
  assert.deepEqual(PE_PACKER_SECTIONS, {
    "bun-standalone": { key: "bun-standalone", title: "Bun standalone executable" },
    "nsis-installer": { key: "nsis-installer", title: "NSIS installer" },
    "upx": { key: "upx", title: "UPX executable packer" }
  });
});

void test("pePackerReportSummary distinguishes verified findings and warnings", () => {
  assert.equal(pePackerReportSummary(report(1, 0)), "verified");
  assert.equal(pePackerReportSummary(report(2, 0)), "2 verified findings");
  assert.equal(pePackerReportSummary(report(0, 1)), "1 warning");
  assert.equal(pePackerReportSummary(report(0, 2)), "2 warnings");
  assert.equal(pePackerReportSummary(report(1, 2)), "verified, 2 warnings");
});

void test("pePackerSectionDescriptors creates analyzer-specific lazy sections", () => {
  assert.deepEqual(pePackerSectionDescriptors({
    reports: [report(1, 0), { ...report(0, 1), id: "nsis-installer" }]
  }), [
    { key: "upx", summary: "verified", title: "UPX executable packer" },
    { key: "nsis-installer", summary: "1 warning", title: "NSIS installer" }
  ]);
  assert.deepEqual(pePackerSectionDescriptors(null), []);
});
