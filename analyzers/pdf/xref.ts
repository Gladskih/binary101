"use strict";
import { extractDictionary, parseTrailerDictionary } from "./dictionary.js";
import type { PdfXref, PdfXrefTable } from "./types.js";

const skipWhitespace = (text: string, position: number): number => {
  let pos = position;
  while (pos < text.length) {
    const ch = text.charAt(pos);
    if (!ch || !/\s/.test(ch)) break;
    pos += 1;
  }
  return pos;
};

const parseXrefTable = (text: string, startOffset: number, issues: string[]): PdfXrefTable | null => {
  let pos = skipWhitespace(text, startOffset);
  if (!text.startsWith("xref", pos)) return null;
  pos += 4;
  const tableBody = text.slice(pos);
  const trailerIndex = tableBody.indexOf("trailer");
  if (trailerIndex === -1) {
    issues.push("xref table found without trailer.");
    return null;
  }
  const lines = tableBody.slice(0, trailerIndex).split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const sections: PdfXrefTable["sections"] = [];
  const entries: PdfXrefTable["entries"] = [];
  let lineIndex = 0;
  while (lineIndex < lines.length) {
    const headerLine = lines[lineIndex];
    if (!headerLine) {
      issues.push("xref subsection header line is missing.");
      break;
    }
    const headerParts = headerLine.split(/\s+/);
    const [startText, countText] = headerParts;
    if (headerParts.length < 2 || !startText || !countText) {
      issues.push("xref subsection header is malformed.");
      break;
    }
    const startObj = Number.parseInt(startText, 10);
    const count = Number.parseInt(countText, 10);
    if (Number.isNaN(startObj) || Number.isNaN(count)) {
      issues.push("xref subsection uses non-numeric bounds.");
      break;
    }
    lineIndex += 1;
    sections.push({ start: startObj, count });
    for (let i = 0; i < count; i += 1) {
      if (lineIndex >= lines.length) {
        issues.push("xref subsection truncated before expected entry count.");
        break;
      }
      const entryLine = lines[lineIndex];
      if (!entryLine) {
        issues.push(`xref entry ${startObj + i} is missing.`);
        lineIndex += 1;
        continue;
      }
      const entryMatch = entryLine.match(/^(\d{10})\s+(\d{5})\s+([fn])/);
      if (!entryMatch) {
        issues.push(`xref entry ${startObj + i} is malformed.`);
        lineIndex += 1;
        continue;
      }
      const offsetText = entryMatch[1];
      const generationText = entryMatch[2];
      const flag = entryMatch[3];
      if (!offsetText || !generationText || !flag) {
        issues.push(`xref entry ${startObj + i} is incomplete.`);
        lineIndex += 1;
        continue;
      }
      const objectNumber = startObj + i;
      entries.push({
        objectNumber,
        offset: Number.parseInt(offsetText, 10),
        generation: Number.parseInt(generationText, 10),
        inUse: flag === "n"
      });
      lineIndex += 1;
      if (entries.length >= 20000) {
        issues.push("xref entry limit reached; further entries are omitted.");
        return { kind: "table", startOffset, sections, entries, trailerText: null };
      }
    }
  }
  const trailerText = tableBody.slice(trailerIndex + "trailer".length).trimStart();
  return { kind: "table", startOffset, sections, entries, trailerText };
};

const parseXrefStream = (text: string, startOffset: number, issues: string[]): PdfXref | null => {
  const pos = skipWhitespace(text, startOffset);
  const objectMatch = text.slice(pos, pos + 64).match(/(\d+)\s+(\d+)\s+obj/);
  if (!objectMatch) return null;
  const objectNumberText = objectMatch[1];
  const generationText = objectMatch[2];
  if (!objectNumberText || !generationText) return null;
  const dict = extractDictionary(text, pos);
  if (!dict || dict.indexOf("/XRef") === -1) return null;
  issues.push("Cross-reference stream detected; detailed entries are not decoded yet.");
  return {
    kind: "stream",
    startOffset,
    objectNumber: Number.parseInt(objectNumberText, 10),
    generation: Number.parseInt(generationText, 10),
    trailer: parseTrailerDictionary(dict)
  };
};

const parseXref = (text: string, startOffset: number | null, issues: string[]): PdfXref | null => {
  if (startOffset == null || Number.isNaN(startOffset)) return null;
  if (startOffset < 0 || startOffset >= text.length) {
    issues.push("startxref offset points outside the file.");
    return null;
  }
  const table = parseXrefTable(text, startOffset, issues);
  if (table) {
    const trailer = parseTrailerDictionary(table.trailerText || "");
    return { ...table, trailer };
  }
  const stream = parseXrefStream(text, startOffset, issues);
  if (stream) return stream;
  issues.push("Unable to read cross-reference information at startxref offset.");
  return null;
};

const buildOffsetMap = (xref: PdfXref | null): Map<number, number> | null => {
  if (!xref || xref.kind !== "table") return null;
  const map = new Map<number, number>();
  xref.entries
    .filter(entry => entry.inUse)
    .forEach(entry => map.set(entry.objectNumber, entry.offset));
  return map;
};

export { buildOffsetMap, parseXref };
