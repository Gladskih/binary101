import assert from "node:assert/strict";
import { test } from "node:test";
import { DOMParser } from "@xmldom/xmldom";
import { getPrologValidationTableModel, renderPrologValidation }
  from "../../../../renderers/pe/prolog-validation.js";
import type { Amd64PrologReport } from "../../../../analyzers/pe/exception/amd64/prolog-types.js";

const report = (): Amd64PrologReport => ({ matchedCount: 1,
  unverifiedCounts: { "chained-unwind": 2, "future-reason": 1 },
  findings: [{ beginRva: 4096, endRva: 4101, unwindInfoRva: 8192,
    issues: [{ code: "operation-mismatch", offset: 4, expected: "recover entry RSP", actual: "<script>" }],
    limitations: ["control-flow", "future-reason"] }]
});

void test("renders factual coverage and escapes instruction and fallback reason text", () => {
  const html = renderPrologValidation(report());
  const document = new DOMParser().parseFromString(`<div>${html}</div>`, "text/html");
  assert.match(html, /Prologs with matching unwind state<\/dt><dd>1/);
  assert.match(html, /Prologs with discrepancies<\/dt><dd>1/);
  assert.match(html, /Prologs not fully checked<\/dt><dd>3/);
  assert.match(html, /Chained unwind context/);
  assert.match(html, /future-reason/);
  assert.ok(html.includes("<div>&lt;script&gt;</div>"));
  assert.equal(document.getElementsByTagName("script").length, 0);
  assert.match(html, /data-pe-special-rva="4096"/);
  assert.match(html, /Partial check:/);
});

void test("resolves only the current prolog findings table", () => {
  assert.equal(getPrologValidationTableModel(undefined, "pe-prolog-validation"), null);
  assert.equal(getPrologValidationTableModel(report(), "unrelated"), null);
  const model = getPrologValidationTableModel(report(), "pe-prolog-validation")!;
  assert.equal(model.rowCount, 1);
  assert.equal(model.rowAt(1), null);
  assert.equal(model.sortValueAt(0, 0), "4096");
  assert.equal(model.sortValueAt(0, 3), "<script>");
  assert.equal(model.sortValueAt(1, 0), "");
  assert.equal(model.sortValueAt(0, 8), "");
  assert.ok(model.searchValueAt!(0).includes("operation-mismatch recover entry RSP <script>"));
  assert.equal(model.searchValueAt!(1), "");
});

void test("renders empty results without a disclosure or empty findings table", () => {
  const html = renderPrologValidation({ matchedCount: 1, findings: [], unverifiedCounts: {} });
  assert.doesNotMatch(html, /<details|<table/);
});

void test("paginates large finding collections and retains every source row", () => {
  const subject = report();
  subject.findings = Array.from({ length: 51 }, (_, index) => ({ ...subject.findings[0]!, beginRva: index }));
  const model = getPrologValidationTableModel(subject, "pe-prolog-validation")!;
  assert.match(renderPrologValidation(subject), /data-paged-sortable-table-id="pe-prolog-validation"/);
  assert.equal(model.rowCount, 51);
  assert.match(model.rowAt(50)!.cells[0]!.html, /data-pe-special-rva="50"/);
});

for (const code of ["operation-boundary", "prolog-size", "operation-mismatch"] as const) {
  void test(`renders ${code} without requiring fabricated operands`, () => {
    const subject = report();
    subject.findings[0]!.issues = [{ code, offset: 0 }];
    subject.findings[0]!.limitations = [];
    const model = getPrologValidationTableModel(subject, "pe-prolog-validation")!;
    assert.match(model.sortValueAt(0, 2), new RegExp(code));
    assert.match(model.sortValueAt(0, 3), new RegExp(code));
    assert.ok(model.rowAt(0)!.cells[2]!.html.length);
    assert.ok(model.rowAt(0)!.cells[3]!.html.length);
  });
}
