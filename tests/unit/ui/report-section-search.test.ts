import assert from "node:assert/strict";
import { test } from "node:test";
import { findReportSectionMatch } from "../../../ui/report-section-search.js";

void test("matches titles and labels independently of recorded values", () => {
  assert.equal(findReportSectionMatch("Dynamic linking", ["DT_RPATH"], " rPaTh "), "DT_RPATH");
  assert.equal(findReportSectionMatch("DOS header", [], "dos"), "DOS header");
  assert.equal(findReportSectionMatch("PE header", ["IMAGE_FILE_DLL"], "file_dll"), "IMAGE_FILE_DLL");
});

void test("treats special characters literally and returns no match for empty queries", () => {
  assert.equal(findReportSectionMatch("Section", ["<a&b.*>"], "b.*"), "<a&b.*>");
  assert.equal(findReportSectionMatch("Section", ["DT_RPATH"], "   "), null);
  assert.equal(findReportSectionMatch("Section", [], "missing"), null);
});
