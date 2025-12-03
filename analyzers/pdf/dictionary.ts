"use strict";
import type {
  PdfCatalog,
  PdfInfoDictionary,
  PdfIndirectRef,
  PdfPages,
  PdfTrailer
} from "./types.js";

const MAX_OBJECT_SCAN = 65536;

const extractDictionary = (text: string, startAt: number): string | null => {
  const dictStart = text.indexOf("<<", startAt);
  if (dictStart === -1) return null;
  let depth = 0;
  for (let i = dictStart; i < text.length - 1; i += 1) {
    const pair = text.slice(i, i + 2);
    if (pair === "<<") {
      depth += 1;
      i += 1;
      continue;
    }
    if (pair === ">>") {
      depth -= 1;
      i += 1;
      if (depth === 0) return text.slice(dictStart, i + 1);
    }
  }
  return null;
};

const parseIndirectRef = (dictText: string, name: string): PdfIndirectRef | null => {
  const pattern = new RegExp(`/${name}\\s+(\\d+)\\s+(\\d+)\\s+R`);
  const match = dictText.match(pattern);
  if (!match) return null;
  const objectNumberText = match[1];
  const generationText = match[2];
  if (!objectNumberText || !generationText) return null;
  return { objectNumber: Number.parseInt(objectNumberText, 10), generation: Number.parseInt(generationText, 10) };
};

const parseTrailerDictionary = (trailerText: string): PdfTrailer => {
  const dict = extractDictionary(trailerText, 0);
  if (!dict) return { raw: trailerText.trim(), size: null, rootRef: null, infoRef: null, id: null };
  const sizeMatch = dict.match(/\/Size\s+(\d+)/);
  const idMatch = dict.match(/\/ID\s*\[\s*<([^>]+)>\s*<([^>]+)>\s*\]/);
  const size = sizeMatch?.[1] ? Number.parseInt(sizeMatch[1], 10) : null;
  const idPart1 = idMatch?.[1];
  const idPart2 = idMatch?.[2];
  let id: [string, string] | null = null;
  if (typeof idPart1 === "string" && typeof idPart2 === "string") {
    id = [idPart1, idPart2];
  }
  return {
    raw: dict.trim(),
    size,
    rootRef: parseIndirectRef(dict, "Root"),
    infoRef: parseIndirectRef(dict, "Info"),
    id
  };
};

const readObjectText = (
  text: string,
  offset: number | undefined,
  issues: string[],
  label: string
): string | null => {
  if (offset == null || offset < 0 || offset >= text.length) {
    issues.push(`${label} offset is outside the file.`);
    return null;
  }
  const slice = text.slice(offset, offset + MAX_OBJECT_SCAN);
  const endIdx = slice.indexOf("endobj");
  if (endIdx === -1) {
    issues.push(`${label} object does not terminate with endobj near offset ${offset}.`);
    return null;
  }
  return slice.slice(0, endIdx);
};

const decodeLiteralString = (value: string): string =>
  value
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\b/g, "\b")
    .replace(/\\f/g, "\f")
    .replace(/\\\(/g, "(")
    .replace(/\\\)/g, ")")
    .replace(/\\\\/g, "\\");

const parseInfoDictionary = (dictText: string | null): PdfInfoDictionary | null => {
  if (!dictText) return null;
  const dict = extractDictionary(dictText, 0);
  if (!dict) return null;
  const parseField = (name: string): string | null => {
    const pattern = new RegExp(String.raw`/${name}\s*\(([^)]*)\)`);
    const match = dict.match(pattern);
    return match?.[1] ? decodeLiteralString(match[1]) : null;
  };
  return {
    raw: dict.trim(),
    title: parseField("Title"),
    author: parseField("Author"),
    subject: parseField("Subject"),
    keywords: parseField("Keywords"),
    creator: parseField("Creator"),
    producer: parseField("Producer"),
    creationDate: parseField("CreationDate"),
    modDate: parseField("ModDate")
  };
};

const parseCatalogDictionary = (dictText: string | null): PdfCatalog | null => {
  if (!dictText) return null;
  const dict = extractDictionary(dictText, 0);
  if (!dict) return null;
  const pagesRef = parseIndirectRef(dict, "Pages");
  const namesRef = parseIndirectRef(dict, "Names");
  const outlinesRef = parseIndirectRef(dict, "Outlines");
  return { raw: dict.trim(), pagesRef, namesRef, outlinesRef };
};

const parsePagesDictionary = (dictText: string | null): PdfPages | null => {
  if (!dictText) return null;
  const dict = extractDictionary(dictText, 0);
  if (!dict) return null;
  const countMatch = dict.match(/\/Count\s+(\d+)/);
  const countText = countMatch?.[1];
  return { raw: dict.trim(), count: countText ? Number.parseInt(countText, 10) : null };
};

export {
  decodeLiteralString,
  extractDictionary,
  parseCatalogDictionary,
  parseInfoDictionary,
  parseIndirectRef,
  parsePagesDictionary,
  parseTrailerDictionary,
  readObjectText
};
