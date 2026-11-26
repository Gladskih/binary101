import assert from "node:assert/strict";
import { test } from "node:test";
import { DOMParser } from "@xmldom/xmldom";
import { parsePdf } from "../../../../analyzers/pdf/index.js";
import {
  renderCatalogFields, renderEmbeddedFileTable, renderPageTable, renderTrailerFields
} from "../../../../renderers/pdf/document-tables.js";
import { createPdfWithEmbeddedFile } from "../../../fixtures/pdf-document-structure.js";

const document = (html: string) => new DOMParser({
  onError: (_level, message) => assert.fail(message)
}).parseFromString("<section>" + html + "</section>", "text/html");

void test("trailer and catalog classify familiar fields and preserve unfamiliar fields as text", () => {
  const fields = [{ key: "Root", value: "4 0 R" }, { key: "PageMode", value: "/UseNone" },
    { key: "constructor", value: "(literal &lt; <example>)" }];
  const trailer = document(renderTrailerFields(fields));
  const catalog = document(renderCatalogFields(fields));
  const trailerRows = Array.from(trailer.getElementsByTagName("tr"), row => row.textContent);
  const catalogRows = Array.from(catalog.getElementsByTagName("tr"), row => row.textContent);
  assert.deepEqual(trailerRows, ["KeyValueMeaning", "/Root4 0 RReference to the document catalog.",
    "/PageMode/UseNone\u2014", "/constructor(literal &lt; <example>)\u2014"]);
  assert.deepEqual(catalogRows, ["KeyValueMeaning", "/Root4 0 R\u2014",
    "/PageMode/UseNoneWhich panels or viewing mode to use when the document opens.",
    "/constructor(literal &lt; <example>)\u2014"]);
  assert.equal(renderTrailerFields([]), "");
});

void test("renders physical page geometry and attachment metadata in shared tables", async () => {
  const parsed = await parsePdf(createPdfWithEmbeddedFile());
  const report = document(renderPageTable(parsed.pages) + renderEmbeddedFileTable(parsed.embeddedFiles));
  assert.deepEqual(Array.from(report.getElementsByTagName("h4"), node => node.textContent),
    ["Pages", "Embedded files"]);
  assert.deepEqual(Array.from(report.getElementsByTagName("table"), node => node.getAttribute("class")),
    ["table", "table"]);
  const rows = Array.from(report.getElementsByTagName("tr"), node => node.textContent);
  assert.deepEqual(rows, [
    "PageObjectMedia size (pt)Crop size (pt)Rotation (°)",
    "13 0 R612 × 792\u201490",
    "25 0 R643 × 916380 × 7600",
    "NameDescriptionFile specificationStreamMedia typeStored bytes (/Length)" +
      "Decoded bytes (/Params /Size)RelationshipSource",
    "notes.txtRead &lt;notes&gt;8 0 R11 0 Rtext/plain44DataEmbeddedFiles name tree, Catalog /AF"
  ]);
  assert.equal(renderPageTable(null), "");
  assert.equal(renderEmbeddedFileTable([]), "");
});

void test("uses unknown placeholders for unavailable geometry and unnamed embedded files", () => {
  const page = { ref: { objectNumber: 10, generation: 0 }, mediaBox: null, cropBox: null,
    rotation: null, userUnit: null };
  const html = renderPageTable({ raw: "", count: 1, entries: [page] }) +
    renderEmbeddedFileTable([{
      name: null, description: null, fileSpec: null, stream: { objectNumber: 23, generation: 0 },
      mediaType: null, storedSize: 0, decodedSize: null, relationship: null, sources: ["Catalog /AF"]
    }]);
  const rows = Array.from(document(html).getElementsByTagName("tbody"), node => node.textContent);
  assert.deepEqual(rows, ["110 0 R\u2014\u2014\u2014", "Unknown\u2014\u201423 0 R\u20140\u2014\u2014Catalog /AF"]);
});
