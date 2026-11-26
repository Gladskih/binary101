import { unsigned } from "./syntax.js";
import type { PdfHeader } from "./types.js";

export const parseHeader = (text: string, issues: string[]): PdfHeader => {
  const [line = "", comment] = text.split(/\r\n?|\n/, 2);
  const headerLine = line.trimEnd();
  const version = /^%PDF-(\d+\.\d+)$/.exec(headerLine)?.[1] ?? null;
  if (!version) issues.push("Missing or malformed %PDF- header.");
  // ISO 32000-2, 7.5.2: binary PDFs mark the header with four or more high bytes.
  const binaryMarker = comment && /^%[\x80-\xff]{4}/.test(comment) ? comment : null;
  return { headerLine, version, binaryMarker };
};

export const parseStartxref = (text: string, issues: string[]): number | null => {
  // ISO 32000-2, 7.5.5: startxref, the offset and %%EOF occupy consecutive lines.
  let end = -1;
  for (const marker of text.matchAll(/(?:^|\r\n|[\r\n])%%EOF[\t ]*(?=[\r\n]|$)/g)) end = marker.index;
  if (end < 0) {
    issues.push("Final %%EOF marker and startxref offset could not be located.");
    return null;
  }
  const footer = /(?:^|[\r\n])startxref[\t ]*(?:\r\n?|\n)[\t ]*(\d+)[\t ]*$/.exec(text.slice(0, end));
  const offset = unsigned(footer?.[1]);
  if (offset == null) issues.push("Missing or invalid startxref offset before %%EOF.");
  return offset;
};
