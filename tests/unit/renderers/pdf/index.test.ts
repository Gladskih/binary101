import assert from "node:assert/strict";
import { test } from "node:test";
import { DOMParser } from "@xmldom/xmldom";
import { parsePdf } from "../../../../analyzers/pdf/index.js";
import type { PdfParseResult } from "../../../../analyzers/pdf/types.js";
import { renderPdf } from "../../../../renderers/pdf/index.js";
import { createPdfMissingStartxref } from "../../../fixtures/pdf-fixtures.js";
import { createHybridPdf, createRevisionPdf, createStreamPdf } from "../../../fixtures/pdf-modern.js";

const reportDocument = (pdf: PdfParseResult) => new DOMParser({
  onError: (_level, message) => assert.fail(message)
}).parseFromString("<section>" + renderPdf(pdf) + "</section>", "text/html");

const fullReport: PdfParseResult = {
  size: 512,
  header: { headerLine: "%PDF-2.0", version: "2.0" },
  startxref: 0,
  revisions: [{
    primary: {
      kind: "stream", offset: 0, object: { objectNumber: 8, generation: 1 },
      sections: [{ start: 0, count: 5 }],
      entries: [
        { kind: "free", objectNumber: 0, nextFree: 0, generation: 65535 },
        { kind: "direct", objectNumber: 1, offset: 10, generation: 1 },
        { kind: "compressed", objectNumber: 2, streamObject: 8, index: 0 },
        { kind: "compressed", objectNumber: 3, streamObject: 8, index: 1 },
        { kind: "unknown", objectNumber: 4, type: 9, second: 0, third: 0 }
      ],
      trailer: {
        raw: "<< /Size 9 /Comment (&lt;x&gt; <y>) >>", size: 9, fields: [
          { key: "Size", value: "9" }, { key: "Comment", value: "(&lt;x&gt; <y>)" }
        ],
        rootRef: { objectNumber: 1, generation: 1 }, infoRef: { objectNumber: 2, generation: 0 },
        id: ["0A", "2B"], prev: null, xrefStreamOffset: null, encrypt: null
      }
    }
  }],
  catalog: {
    raw: "<< /Type /Catalog /Comment (&lt;x&gt; <y>) >>",
    fields: [{ key: "Type", value: "/Catalog" }, { key: "Comment", value: "(&lt;x&gt; <y>)" }],
    pagesRef: { objectNumber: 3, generation: 0 },
    namesRef: { objectNumber: 4, generation: 1 },
    outlinesRef: { objectNumber: 5, generation: 2 }
  },
  pages: { count: 0, raw: "<< /Count 0 >>", entries: [] },
  embeddedFiles: [],
  info: {
    raw: "<< /Title (Survey &lt;examples&gt; <2026>) >>",
    title: "Survey &lt;examples&gt; <2026>", author: "A", subject: "B", keywords: "C",
    creator: "D", producer: "E", creationDate: "D:20260201", modDate: "D:20260301"
  },
  issues: ["First warning &lt;x&gt;", "Second warning <entry>"]
};

void test("PDF report preserves all document information and raw dictionary text", () => {
  const report = reportDocument(fullReport);
  const info = report.getElementsByTagName("table")[3]!;
  assert.equal(info.getAttribute("class"), "table");
  assert.deepEqual(Array.from(report.getElementsByTagName("div"), node => node.getAttribute("class")),
    ["tableWrap", "tableWrap", "tableWrap", "tableWrap"]);
  assert.deepEqual(Array.from(info.getElementsByTagName("th"), node => node.getAttribute("scope")),
    ["col", "col", ...Array<string>(8).fill("row")]);
  assert.deepEqual(Array.from(info.getElementsByTagName("tr"), row => row.textContent), [
    "FieldValue", "TitleSurvey &lt;examples&gt; <2026>", "AuthorA", "SubjectB", "KeywordsC",
    "CreatorD", "ProducerE", "CreatedD:20260201", "ModifiedD:20260301"
  ]);
  assert.deepEqual(Array.from(report.getElementsByTagName("dd"), node =>
    node.getElementsByTagName("code")[0]?.textContent).filter(Boolean),
    [fullReport.revisions[0]?.primary.trailer?.raw, fullReport.catalog?.raw]);
  assert.deepEqual(Array.from(report.getElementsByTagName("li"), node => node.textContent),
    ["First warning &lt;x&gt;", "Second warning <entry>"]);
  assert.equal(report.getElementsByTagName("entry").length, 0);
  assert.equal(report.getElementsByTagName("ul")[0]?.getAttribute("class"), "issueList");
});

void test("PDF report labels each section and preserves zero counts and offsets", () => {
  const report = reportDocument(fullReport);
  assert.equal(report.getElementsByTagName("h3")[0]?.textContent, "PDF structure");
  assert.deepEqual(Array.from(report.getElementsByTagName("h4"), node => node.textContent),
    ["Cross-reference", "Trailer", "Catalog", "Document information", "Warnings"]);
  assert.deepEqual(Array.from(report.getElementsByTagName("dl"), node => node.textContent), [
    "File size512 B (512 bytes)Header%PDF-2.0Version2.0startxref0",
    "Raw dictionary<< /Size 9 /Comment (&lt;x&gt; <y>) >>",
    "Declared page count0Raw catalog<< /Type /Catalog /Comment (&lt;x&gt; <y>) >>"
  ]);
  assert.deepEqual(Array.from(report.getElementsByTagName("dt"), node => node.getAttribute("title"))
    .filter(Boolean), [
    "Byte offset recorded after the final startxref keyword.",
    "/Count from the page tree root."
  ]);
});

void test("PDF xref counters are attached to their own numeric columns and section row", () => {
  const report = reportDocument(fullReport);
  const table = report.getElementsByTagName("table")[0]!;
  const headers = table.getElementsByTagName("thead")[0]!.getElementsByTagName("th");
  const row = table.getElementsByTagName("tbody")[0]!.getElementsByTagName("tr")[0]!;
  assert.equal(table.parentNode?.nodeName, "div");
  assert.equal(table.getAttribute("class"), "table");
  assert.deepEqual(Array.from(headers, header => header.textContent),
    ["Section", "File offset", "Subsections", "Uncompressed", "Compressed", "Free", "Unknown type"]);
  assert.deepEqual(Array.from(headers, header => header.getAttribute("scope")), Array(7).fill("col"));
  assert.deepEqual(Array.from(headers, header => header.getAttribute("class")),
    [null, ...Array<string>(6).fill("peNumeric")]);
  assert.equal(row.getElementsByTagName("th")[0]?.textContent, "Stream (8 1 R)");
  assert.equal(row.getElementsByTagName("th")[0]?.getAttribute("scope"), "row");
  assert.deepEqual(Array.from(row.getElementsByTagName("td"), cell => cell.textContent), ["0", "1", "1", "2", "1", "1"]);
  assert.deepEqual(Array.from(row.getElementsByTagName("td"), cell => cell.getAttribute("class")),
    Array(6).fill("peNumeric"));
});

void test("PDF report renders a hybrid reference stream alongside its tables", async () => {
  const html = renderPdf(await parsePdf(createHybridPdf(false)));
  assert.match(html, /Supplemental stream \(6 0 R\)/);
  assert.match(html, /<th scope="col" class="peNumeric">Compressed<\/th>/);
  assert.match(html, /Declared page count/);
  assert.match(html, /Proof of \(nested\) strings/);
  assert.doesNotMatch(html, /Warnings/);
});

void test("PDF report shows unavailable xref counts and escaped warnings", async () => {
  const pdf = await parsePdf(createStreamPdf("unsupported"));
  const html = renderPdf({ ...pdf, issues: [...pdf.issues, "<unreadable>"] });
  assert.match(html, /Stream \(6 0 R\)/);
  assert.match(html, /<td class="peNumeric">—<\/td>/);
  assert.match(html, /unsupported filter/);
  assert.match(html, /&lt;unreadable/);
  assert.doesNotMatch(html, /<unreadable>/);
  assert.doesNotMatch(html, /Document information/);
});

void test("PDF report exposes the trailer Encrypt declaration without showing Info", async () => {
  const pdf = await parsePdf(createRevisionPdf("encrypted"));
  const html = renderPdf(pdf);
  assert.match(html, /<th scope="row">\/Encrypt<\/th><td><code>7 0 R<\/code><\/td>/);
  assert.match(html, /<code>7 0 R<\/code>/);
  assert.doesNotMatch(html, /Latest revision/);
});

void test("PDF report distinguishes missing metadata and unavailable xref counts from zero", () => {
  const trailer = { raw: "<< >>", fields: [], size: null, rootRef: null, infoRef: null,
    id: null, prev: null, xrefStreamOffset: null, encrypt: null };
  const report = reportDocument({
    ...fullReport, header: { headerLine: "", version: null }, startxref: null,
    revisions: [{ primary: { kind: "table", offset: 12, sections: [], entries: null, trailer } }],
    catalog: { raw: "<< >>", fields: [], pagesRef: null, namesRef: null, outlinesRef: null }, pages: null,
    issues: [], info: {
      raw: "<< >>", title: null, author: null, subject: null, keywords: null,
      creator: null, producer: null, creationDate: null, modDate: null
    }
  });
  assert.deepEqual(Array.from(report.getElementsByTagName("dl"), node => node.textContent), [
    "File size512 B (512 bytes)HeaderMissingVersionUnknownstartxrefMissing",
    "Raw dictionary<< >>",
    "Raw catalog<< >>"
  ]);
  assert.deepEqual(Array.from(report.getElementsByTagName("td"), node => node.textContent),
    ["12", ...Array<string>(5).fill("\u2014")]);
  assert.deepEqual(Array.from(report.getElementsByTagName("h4"), node => node.textContent),
    ["Cross-reference", "Trailer", "Catalog"]);
});

void test("PDF report with no parsed structure renders its footer warning", async () => {
  assert.match(renderPdf(await parsePdf(createPdfMissingStartxref())), /invalid startxref offset/);
  assert.equal(renderPdf(null), "");
});
