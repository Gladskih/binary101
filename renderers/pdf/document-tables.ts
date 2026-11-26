import { escapeHtmlText } from "../../html-utils.js";
import type {
  PdfDictionaryField, PdfEmbeddedFile, PdfIndirectRef, PdfPages, PdfRectangle
} from "../../analyzers/pdf/types.js";

const missing = "\u2014";

// ISO 32000-2, Tables 15 and 17 (trailer and cross-reference stream).
const trailerMeanings: Readonly<Record<string, string>> = {
  Size: "One more than the highest object number.",
  Root: "Reference to the document catalog.",
  Info: "Reference to the document information dictionary.",
  ID: "Permanent and changing file identifiers.",
  Prev: "File offset of the preceding cross-reference section.",
  XRefStm: "File offset of the supplemental cross-reference stream.",
  Encrypt: "Document encryption dictionary.",
  Type: "Object type.",
  W: "Byte widths of the cross-reference entry fields.",
  Index: "First object number and entry count for each subsection.",
  Length: "Number of stored stream bytes.",
  Filter: "Filters used to decode stream data.",
  DecodeParms: "Parameters for the stream filters."
};

// ISO 32000-2, Table 29 (document catalog).
const catalogMeanings: Readonly<Record<string, string>> = {
  Type: "Object type.",
  Pages: "Reference to the root of the page tree.",
  PageMode: "Which panels or viewing mode to use when the document opens.",
  PageLayout: "Page arrangement when the document opens.",
  Names: "Document name trees, including named destinations and embedded files.",
  Outlines: "Reference to the document outline.",
  Metadata: "Reference to the document metadata stream.",
  AcroForm: "Interactive form dictionary.",
  Lang: "Default language of the document.",
  OpenAction: "Destination or action specified for document open.",
  AF: "File specifications associated with the document.",
  Version: "PDF version declared by the catalog.",
  ViewerPreferences: "Document viewing and printing preferences.",
  StructTreeRoot: "Reference to the logical structure tree.",
  MarkInfo: "Information about the use of marked content."
};

const table = (columns: string[], rows: string): string =>
  '<div class="tableWrap"><table class="table"><thead><tr>' + columns.join("") +
  "</tr></thead><tbody>" + rows + "</tbody></table></div>";

const column = (label: string): string => '<th scope="col">' + label + "</th>";

const numericColumn = (label: string): string =>
  '<th scope="col" class="peNumeric">' + label + "</th>";

const labelCell = (text: string): string => '<th scope="row">' + escapeHtmlText(text) + "</th>";

const cell = (text: string | null): string => "<td>" + escapeHtmlText(text ?? missing) + "</td>";

const numericCell = (value: number | null): string =>
  '<td class="peNumeric">' + (value ?? missing) + "</td>";

const reference = (ref: PdfIndirectRef | null): string | null =>
  ref ? String(ref.objectNumber) + " " + ref.generation + " R" : null;

const renderFields = (fields: PdfDictionaryField[], meanings: Readonly<Record<string, string>>): string => {
  if (!fields.length) return "";
  const rows = fields.map(({ key, value }) => "<tr>" + labelCell("/" + key) +
    "<td><code>" + escapeHtmlText(value) + "</code></td>" +
    cell(Object.hasOwn(meanings, key) ? meanings[key]! : null) + "</tr>").join("");
  return table(["Key", "Value", "Meaning"].map(column), rows);
};

export const renderTrailerFields = (fields: PdfDictionaryField[]): string =>
  renderFields(fields, trailerMeanings);

export const renderCatalogFields = (fields: PdfDictionaryField[]): string =>
  renderFields(fields, catalogMeanings);

const pageSize = (box: PdfRectangle | null, unit: number | null): string | null => {
  if (!box || unit == null) return null;
  const [left, bottom, right, top] = box;
  const width = Math.abs(right - left) * unit;
  const height = Math.abs(top - bottom) * unit;
  if (!Number.isFinite(width) || !Number.isFinite(height)) return null;
  return Number(width.toFixed(2)) + " × " + Number(height.toFixed(2));
};

export const renderPageTable = (pages: PdfPages | null): string => {
  if (!pages?.entries.length) return "";
  const rows = pages.entries.map((page, index) => "<tr>" + labelCell(String(index + 1)) +
    cell(reference(page.ref)) + cell(pageSize(page.mediaBox, page.userUnit)) +
    cell(pageSize(page.cropBox, page.userUnit)) + numericCell(page.rotation) + "</tr>").join("");
  const columns = ["Page", "Object", "Media size (pt)", "Crop size (pt)"].map(column);
  return "<h4>Pages</h4>" + table([...columns, numericColumn("Rotation (°)")], rows);
};

export const renderEmbeddedFileTable = (files: PdfEmbeddedFile[]): string => {
  if (!files.length) return "";
  const rows = files.map(file => "<tr>" + labelCell(file.name ?? "Unknown") + cell(file.description) +
    cell(reference(file.fileSpec)) + cell(reference(file.stream)) + cell(file.mediaType) +
    numericCell(file.storedSize) + numericCell(file.decodedSize) + cell(file.relationship) +
    cell(file.sources.join(", ")) + "</tr>").join("");
  const columns = ["Name", "Description", "File specification", "Stream", "Media type"].map(column);
  return "<h4>Embedded files</h4>" + table([...columns, numericColumn("Stored bytes (/Length)"),
    numericColumn("Decoded bytes (/Params /Size)"), column("Relationship"), column("Source")], rows);
};
