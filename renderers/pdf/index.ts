"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";
import type {
  PdfCatalog,
  PdfInfoDictionary,
  PdfParseResult,
  PdfPages,
  PdfTrailer,
  PdfXref
} from "../../analyzers/pdf/types.js";

function renderIssues(issues: string[] | null | undefined): string {
  if (!issues || issues.length === 0) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
}

function renderCrossReference(xref: PdfXref | null): string {
  if (!xref) return "";
  if (xref.kind === "stream") {
    return (
      "<h4>Cross-reference</h4>" +
      "<p>Found cross-reference stream; entry decoding is not implemented yet.</p>" +
      "<dl>" +
      renderDefinitionRow("Object", `${xref.objectNumber} ${xref.generation} R`) +
      (xref.trailer && xref.trailer.size
        ? renderDefinitionRow("Declared objects", String(xref.trailer.size))
        : "") +
      "</dl>"
    );
  }
  const entryCount = xref.entries ? xref.entries.length : 0;
  const subsectionCount = xref.sections ? xref.sections.length : 0;
  const freeEntries = xref.entries ? xref.entries.filter(e => !e.inUse).length : 0;
  const rows = (xref.sections || [])
    .map((section, idx) => {
      const start = section.start != null ? section.start : "?";
      const count = section.count != null ? section.count : "?";
      return `<tr><td>${idx}</td><td>${start}</td><td>${count}</td></tr>`;
    })
    .join("");
  const tableHtml = subsectionCount
    ? '<table class="byteView"><thead><tr><th>#</th><th>Start</th><th>Count</th></tr></thead>' +
      `<tbody>${rows}</tbody></table>`
    : "<p>No subsections recorded.</p>";
  return (
    "<h4>Cross-reference</h4>" +
    "<dl>" +
    renderDefinitionRow("Entries parsed", String(entryCount)) +
    renderDefinitionRow("Free entries", String(freeEntries)) +
    renderDefinitionRow("Subsections", String(subsectionCount)) +
    "</dl>" +
    tableHtml
  );
}

function renderTrailer(trailer: PdfTrailer | null): string {
  if (!trailer) return "";
  const parts: string[] = [];
  parts.push("<h4>Trailer</h4><dl>");
  parts.push(
    renderDefinitionRow(
      "Declared objects",
      trailer.size != null ? String(trailer.size) : "Unknown"
    )
  );
  parts.push(
    renderDefinitionRow(
      "Root",
      trailer.rootRef
        ? `${trailer.rootRef.objectNumber} ${trailer.rootRef.generation} R`
        : "Missing",
      "Root (catalog) object reference declared by the trailer."
    )
  );
  parts.push(
    renderDefinitionRow(
      "Info",
      trailer.infoRef
        ? `${trailer.infoRef.objectNumber} ${trailer.infoRef.generation} R`
        : "Missing",
      "Document information dictionary reference if present."
    )
  );
  if (trailer.id && trailer.id.length === 2) {
    parts.push(
      renderDefinitionRow(
        "ID",
        `${escapeHtml(trailer.id[0])} / ${escapeHtml(trailer.id[1])}`
      )
    );
  }
  if (trailer.raw) {
    parts.push(
      renderDefinitionRow(
        "Raw dictionary",
        `<code>${escapeHtml(trailer.raw)}</code>`
      )
    );
  }
  parts.push("</dl>");
  return parts.join("");
}

function renderInfo(info: PdfInfoDictionary | null): string {
  if (!info) return "";
  const rows = [
    ["Title", info.title],
    ["Author", info.author],
    ["Subject", info.subject],
    ["Keywords", info.keywords],
    ["Creator", info.creator],
    ["Producer", info.producer],
    ["Created", info.creationDate],
    ["Modified", info.modDate]
  ]
    .filter(([, value]) => value != null)
    .map(
      ([label, value]) =>
        `<tr><td>${label}</td><td>${escapeHtml(String(value))}</td></tr>`
    )
    .join("");
  if (!rows) return "";
  return (
    "<h4>Document information</h4>" +
    '<table class="byteView">' +
    "<thead><tr><th>Field</th><th>Value</th></tr></thead>" +
    `<tbody>${rows}</tbody></table>`
  );
}

function renderCatalog(catalog: PdfCatalog | null, pages: PdfPages | null): string {
  if (!catalog) return "";
  const rows: string[] = [];
  rows.push(
    renderDefinitionRow(
      "Pages",
      catalog.pagesRef
        ? `${catalog.pagesRef.objectNumber} ${catalog.pagesRef.generation} R`
        : "Missing"
    )
  );
  if (pages && pages.count != null) {
    rows.push(
      renderDefinitionRow(
        "Page count",
        String(pages.count),
        "Declared /Count from the Pages tree root."
      )
    );
  }
  if (catalog.namesRef) {
    rows.push(
      renderDefinitionRow(
        "Names",
        `${catalog.namesRef.objectNumber} ${catalog.namesRef.generation} R`
      )
    );
  }
  if (catalog.outlinesRef) {
    rows.push(
      renderDefinitionRow(
        "Outlines",
        `${catalog.outlinesRef.objectNumber} ${catalog.outlinesRef.generation} R`
      )
    );
  }
  rows.push(
    renderDefinitionRow(
      "Raw catalog",
      catalog.raw ? `<code>${escapeHtml(catalog.raw)}</code>` : "Unavailable"
    )
  );
  return "<h4>Catalog</h4><dl>" + rows.join("") + "</dl>";
}

export function renderPdf(pdf: PdfParseResult | null): string {
  if (!pdf) return "";
  const parts: string[] = [];
  parts.push("<h3>PDF structure</h3>");
  parts.push("<dl>");
  parts.push(
    renderDefinitionRow("File size", escapeHtml(formatHumanSize(pdf.size)))
  );
  parts.push(
    renderDefinitionRow(
      "Header",
      pdf.header && pdf.header.headerLine
        ? escapeHtml(pdf.header.headerLine)
        : "Missing"
    )
  );
  parts.push(
    renderDefinitionRow(
      "Version",
      pdf.header && pdf.header.version ? pdf.header.version : "Unknown"
    )
  );
  parts.push(
    renderDefinitionRow(
      "startxref",
      pdf.startxref != null ? String(pdf.startxref) : "Not found",
      "Offset (from start of file) where xref lookup begins."
    )
  );
  parts.push(renderDefinitionRow("Cross-reference type", pdf.xref ? pdf.xref.kind : "Unknown"));
  parts.push("</dl>");
  parts.push(renderCrossReference(pdf.xref));
  parts.push(renderTrailer(pdf.trailer));
  parts.push(renderCatalog(pdf.catalog, pdf.pages));
  parts.push(renderInfo(pdf.info));
  parts.push(renderIssues(pdf.issues));
  return parts.join("");
}
