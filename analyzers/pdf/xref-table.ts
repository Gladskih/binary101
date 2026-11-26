import { parseTrailerDictionary } from "./dictionary.js";
import { readDictionary, skipTrivia, unsigned } from "./syntax.js";
import type { PdfXref, PdfXrefEntry, PdfXrefSection } from "./types.js";

export const xrefKeyword = /^xref(?=[\0\t\n\f\r ])/;

const subsectionLine = /(\d+)[\t ]+(\d+)[\t ]*(?:\r\n?|\n)/y;
const entryLine = /(\d{10}) (\d{5}) ([fn]) ?(?:\r\n?|\n)/y;

const readEntries = (
  text: string, start: number, count: number, position: number, entries: Map<number, PdfXrefEntry>
): number => {
  entryLine.lastIndex = position;
  for (let i = 0; i < count; i += 1) {
    const row = entryLine.exec(text);
    const objectNumber = start + i;
    if (!row) throw new Error("malformed or truncated entry " + objectNumber);
    if (entries.has(objectNumber)) throw new Error("overlapping subsections");
    const generation = Number(row[2]);
    const location = Number(row[1]);
    if (generation > 65535) throw new Error("invalid generation for entry " + objectNumber);
    entries.set(objectNumber, row[3] === "n"
      ? { objectNumber, generation, kind: "direct", offset: location }
      : { objectNumber, generation, kind: "free", nextFree: location });
  }
  return entryLine.lastIndex;
};

const readTable = (text: string, budget: number): {
  sections: PdfXrefSection[]; entries: PdfXrefEntry[]; trailerOffset: number;
} => {
  const entries = new Map<number, PdfXrefEntry>();
  const sections: PdfXrefSection[] = [];
  let position = skipTrivia(text, 4);
  while (!/^trailer(?=[\0\t\n\f\r <])/.test(text.slice(position, position + 8))) {
    subsectionLine.lastIndex = position;
    const line = subsectionLine.exec(text);
    if (!line) throw new Error("missing trailer or malformed subsection");
    const start = unsigned(line[1]);
    const count = unsigned(line[2]);
    if (start == null || !count || !Number.isSafeInteger(start + count)) {
      throw new Error("invalid subsection bounds");
    }
    if (count > budget - entries.size) throw new Error("xref entry limit reached");
    sections.push({ start, count });
    position = skipTrivia(text, readEntries(text, start, count, subsectionLine.lastIndex, entries));
  }
  return { sections, entries: [...entries.values()], trailerOffset: position + 7 };
};

export const parseXrefTable = (
  text: string, offset: number, budget: number, issues: string[]
): PdfXref => {
  try {
    const { sections, entries, trailerOffset } = readTable(text, budget);
    const dictionary = readDictionary(text, trailerOffset);
    if (!dictionary) throw new Error("missing or malformed trailer dictionary");
    const trailer = parseTrailerDictionary(dictionary, issues);
    if (!trailer.size || sections.some(section => section.start + section.count > trailer.size!)) {
      issues.push("Cross-reference table at " + offset + " has an inconsistent /Size.");
    }
    return { kind: "table", offset, sections, entries, trailer };
  } catch (error) {
    issues.push("Cross-reference table at " + offset + ": " +
      (error instanceof Error ? error.message : String(error)) + ".");
    return { kind: "table", offset, sections: [], entries: null, trailer: null };
  }
};
