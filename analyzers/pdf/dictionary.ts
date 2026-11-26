import { readArray, readReference, unsigned } from "./syntax.js";
import type { PdfDictionary } from "./syntax.js";
import type { PdfCatalog, PdfInfoDictionary, PdfPages, PdfTrailer } from "./types.js";

const hexDigits = (value: string | undefined): string | null =>
  value?.startsWith("<") ? value.slice(1, -1).replace(/[\0\t\n\f\r ]/g, "") : null;

const readIdentifier = (value: string | undefined): [string, string] | null => {
  const items = readArray(value);
  if (items?.length !== 2) return null;
  const first = hexDigits(items[0]);
  const second = hexDigits(items[1]);
  return first != null && second != null ? [first, second] : null;
};

const optionalValue = (fields: PdfDictionary["fields"], key: string): string | undefined => {
  const token = fields.get(key);
  return token === "null" ? undefined : token;
};

const trailerOffset = (fields: PdfDictionary["fields"], key: string, issues: string[]): number | null => {
  const token = optionalValue(fields, key);
  const offset = unsigned(token);
  if (token != null && offset == null) issues.push("Invalid /" + key + " byte offset in trailer.");
  return offset;
};

export const parseTrailerDictionary = ({ raw, fields }: PdfDictionary, issues: string[]): PdfTrailer => ({
  raw,
  fields: Array.from(fields, ([key, value]) => ({ key, value })),
  size: unsigned(fields.get("Size")),
  rootRef: readReference(fields.get("Root")),
  infoRef: readReference(fields.get("Info")),
  id: readIdentifier(fields.get("ID")),
  prev: trailerOffset(fields, "Prev", issues),
  xrefStreamOffset: trailerOffset(fields, "XRefStm", issues),
  encrypt: optionalValue(fields, "Encrypt") ?? null
});

// ISO 32000-2, 7.3.4.2: literal byte strings allow escapes, octal bytes and line continuations.
const escapes: Readonly<Record<string, string>> = { n: "\n", r: "\r", t: "\t", b: "\b", f: "\f" };

export const decodeLiteralString = (value: string): string =>
  value.replace(/\\([0-7]{1,3}|\r\n|[\s\S])|\r\n?/g, (sequence, escaped?: string) => {
    if (escaped == null) return "\n";
    if (escaped.startsWith("\r") || escaped === "\n") return "";
    if (/^[0-7]/.test(escaped)) return String.fromCharCode(Number.parseInt(escaped, 8) & 255);
    return escapes[escaped] ?? sequence.slice(1);
  });

const stringBytes = (value: string | undefined): Uint8Array | null => {
  if (value?.startsWith("(")) {
    return Uint8Array.from(decodeLiteralString(value.slice(1, -1)), char => char.charCodeAt(0));
  }
  const digits = hexDigits(value);
  if (digits == null) return null;
  return Uint8Array.from((digits.match(/.{1,2}/g) ?? []),
    pair => Number.parseInt(pair.padEnd(2, "0"), 16));
};

// PDF 1.7 Reference, Appendix D.2: PDFDocEncoding differs from Latin-1 at these byte ranges.
const diacritics = "\u02d8\u02c7\u02c6\u02d9\u02dd\u02db\u02da\u02dc";
const punctuation = "\u2022\u2020\u2021\u2026\u2014\u2013\u0192\u2044\u2039\u203a\u2212" +
  "\u2030\u201e\u201c\u201d\u2018\u2019\u201a\u2122\ufb01\ufb02\u0141\u0152\u0160\u0178" +
  "\u017d\u0131\u0142\u0153\u0161\u017e\ufffd\u20ac";

const pdfDocCharacter = (byte: number): string => {
  if (byte === 0x7f || byte === 0xad) return "\ufffd";
  return diacritics[byte - 0x18] ?? punctuation[byte - 0x80] ?? String.fromCharCode(byte);
};

export const readPdfTextString = (value: string | undefined): string | null => {
  const bytes = stringBytes(value);
  if (!bytes) return null;
  // ISO 32000-2, 7.9.2.2: Unicode text strings carry a UTF-16BE or UTF-8 BOM.
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return new TextDecoder("utf-16be").decode(bytes);
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return new TextDecoder().decode(bytes);
  }
  return Array.from(bytes, pdfDocCharacter).join("");
};

export const parseInfoDictionary = ({ raw, fields }: PdfDictionary): PdfInfoDictionary => ({
  raw,
  title: readPdfTextString(fields.get("Title")),
  author: readPdfTextString(fields.get("Author")),
  subject: readPdfTextString(fields.get("Subject")),
  keywords: readPdfTextString(fields.get("Keywords")),
  creator: readPdfTextString(fields.get("Creator")),
  producer: readPdfTextString(fields.get("Producer")),
  creationDate: readPdfTextString(fields.get("CreationDate")),
  modDate: readPdfTextString(fields.get("ModDate"))
});

export const parseCatalogDictionary = ({ raw, fields }: PdfDictionary): PdfCatalog => ({
  raw,
  fields: Array.from(fields, ([key, value]) => ({ key, value })),
  pagesRef: readReference(fields.get("Pages")),
  namesRef: readReference(fields.get("Names")),
  outlinesRef: readReference(fields.get("Outlines"))
});

export const parsePagesDictionary = ({ raw, fields }: PdfDictionary): Pick<PdfPages, "raw" | "count"> => ({
  raw,
  count: unsigned(fields.get("Count"))
});
