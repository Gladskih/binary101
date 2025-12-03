"use strict";
import {
  parseCatalogDictionary,
  parseInfoDictionary,
  parsePagesDictionary,
  readObjectText
} from "./dictionary.js";
import { parseHeader, parseStartxref } from "./header.js";
import { buildOffsetMap, parseXref } from "./xref.js";
import type {
  PdfCatalog,
  PdfInfoDictionary,
  PdfPages,
  PdfParseResult,
  PdfTrailer
} from "./types.js";

const decoder = new TextDecoder("latin1", { fatal: false });

const parsePdf = async (file: File): Promise<PdfParseResult | null> => {
  const buffer = await file.arrayBuffer();
  const text = decoder.decode(buffer);
  const issues: string[] = [];
  const header = parseHeader(text, issues);
  const startxref = parseStartxref(text, issues);
  const xref = parseXref(text, startxref, issues);
  const trailer: PdfTrailer | null = xref && "trailer" in xref ? xref.trailer || null : null;
  const offsets = buildOffsetMap(xref);

  let info: PdfInfoDictionary | null = null;
  let catalog: PdfCatalog | null = null;
  let pages: PdfPages | null = null;

  if (offsets && trailer && trailer.infoRef) {
    const infoOffset = offsets.get(trailer.infoRef.objectNumber);
    const infoText = readObjectText(text, infoOffset, issues, "Info");
    info = parseInfoDictionary(infoText);
  }

  if (offsets && trailer && trailer.rootRef) {
    const rootOffset = offsets.get(trailer.rootRef.objectNumber);
    const catalogText = readObjectText(text, rootOffset, issues, "Catalog");
    catalog = parseCatalogDictionary(catalogText);
    if (catalog && catalog.pagesRef) {
      const pagesOffset = offsets.get(catalog.pagesRef.objectNumber);
      const pagesText = readObjectText(text, pagesOffset, issues, "Pages");
      pages = parsePagesDictionary(pagesText);
    }
  }

  return {
    size: buffer.byteLength,
    header,
    startxref,
    xref,
    trailer,
    info,
    catalog,
    pages,
    issues
  };
};

export { parsePdf };
