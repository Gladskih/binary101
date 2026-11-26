import { escapeHtmlText, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";
import type {
  PdfCatalog, PdfIndirectRef, PdfInfoDictionary, PdfPages, PdfParseResult, PdfRevision, PdfTrailer,
  PdfXref
} from "../../analyzers/pdf/types.js";
import { renderCatalogFields, renderEmbeddedFileTable, renderPageTable, renderTrailerFields } from "./document-tables.js";

const reference = (ref: PdfIndirectRef): string =>
  String(ref.objectNumber) + " " + ref.generation + " R";

const numericCell = (text: number | string): string => '<td class="peNumeric">' + text + "</td>";

const renderXrefRow = (xref: PdfXref, label: string): string => {
  const counts = { direct: 0, compressed: 0, free: 0, unknown: 0 };
  for (const entry of xref.entries ?? []) counts[entry.kind] += 1;
  const cells = Object.values(counts).map(count => numericCell(xref.entries ? count : "—"));
  const object = xref.kind === "stream" ? " (" + reference(xref.object) + ")" : "";
  return "<tr><th scope=\"row\">" + label + object + "</th>" + numericCell(xref.offset) +
    numericCell(xref.sections.length || "—") + cells.join("") + "</tr>";
};

const renderCrossReference = (revisions: PdfRevision[]): string => {
  if (!revisions.length) return "";
  const columns = ["File offset", "Subsections", "Uncompressed", "Compressed", "Free", "Unknown type"];
  const headers = columns.map(label => '<th scope="col" class="peNumeric">' + label + "</th>");
  const rows = revisions.map(({ primary, supplement }) =>
    renderXrefRow(primary, primary.kind === "stream" ? "Stream" : "Table") +
    (supplement ? renderXrefRow(supplement, "Supplemental stream") : "")).join("");
  return '<h4>Cross-reference</h4><div class="tableWrap"><table class="table">' +
    '<thead><tr><th scope="col">Section</th>' + headers.join("") +
    "</tr></thead><tbody>" + rows + "</tbody></table></div>";
};

const renderTrailer = (trailer: PdfTrailer | null): string => {
  if (!trailer) return "";
  return "<h4>Trailer</h4>" + renderTrailerFields(trailer.fields) + "<dl>" +
    renderDefinitionRow("Raw dictionary", "<code>" + escapeHtmlText(trailer.raw) + "</code>") + "</dl>";
};

const renderInfo = (info: PdfInfoDictionary | null): string => {
  if (!info) return "";
  const rows = [
    ["Title", info.title], ["Author", info.author], ["Subject", info.subject],
    ["Keywords", info.keywords], ["Creator", info.creator], ["Producer", info.producer],
    ["Created", info.creationDate], ["Modified", info.modDate]
  ].filter(([, value]) => value != null).map(([label, value]) =>
    "<tr><th scope=\"row\">" + label + "</th><td>" + escapeHtmlText(value) + "</td></tr>"
  ).join("");
  if (!rows) return "";
  return '<h4>Document information</h4><div class="tableWrap"><table class="table">' +
    '<thead><tr><th scope="col">Field</th><th scope="col">Value</th></tr></thead>' +
    "<tbody>" + rows + "</tbody></table></div>";
};

const renderCatalog = (catalog: PdfCatalog | null, pages: PdfPages | null): string => {
  if (!catalog) return "";
  const count = pages?.count == null ? "" : renderDefinitionRow("Declared page count",
    String(pages.count), "/Count from the page tree root.");
  return "<h4>Catalog</h4>" + renderCatalogFields(catalog.fields) + "<dl>" + count +
    renderDefinitionRow("Raw catalog", "<code>" + escapeHtmlText(catalog.raw) + "</code>") + "</dl>";
};

const renderIssues = (issues: string[]): string => {
  if (!issues.length) return "";
  const items = issues.map(issue => "<li>" + escapeHtmlText(issue) + "</li>").join("");
  return '<h4>Warnings</h4><ul class="issueList">' + items + "</ul>";
};

export const renderPdf = (pdf: PdfParseResult | null): string => {
  if (!pdf) return "";
  return "<h3>PDF structure</h3><dl>" +
    renderDefinitionRow("File size", escapeHtmlText(formatHumanSize(pdf.size))) +
    renderDefinitionRow("Header", escapeHtmlText(pdf.header.headerLine || "Missing")) +
    renderDefinitionRow("Version", pdf.header.version ?? "Unknown") +
    renderDefinitionRow("startxref", pdf.startxref == null ? "Missing" : String(pdf.startxref),
      "Byte offset recorded after the final startxref keyword.") +
    "</dl>" + renderCrossReference(pdf.revisions) + renderTrailer(pdf.revisions[0]?.primary.trailer ?? null) +
    renderCatalog(pdf.catalog, pdf.pages) + renderPageTable(pdf.pages) + renderEmbeddedFileTable(pdf.embeddedFiles) +
    renderInfo(pdf.info) + renderIssues(pdf.issues);
};
