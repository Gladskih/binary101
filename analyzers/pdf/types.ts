"use strict";

export interface PdfIndirectRef {
  objectNumber: number;
  generation: number;
}

export interface PdfHeader {
  headerLine: string;
  version: string | null;
  binaryMarker?: string | null;
}

export interface PdfXrefEntry {
  objectNumber: number;
  offset: number;
  generation: number;
  inUse: boolean;
}

export interface PdfXrefSection {
  start: number;
  count: number;
}

export interface PdfTrailer {
  raw: string;
  size: number | null;
  rootRef: PdfIndirectRef | null;
  infoRef: PdfIndirectRef | null;
  id: [string, string] | null;
}

export interface PdfXrefTable {
  kind: "table";
  startOffset: number;
  sections: PdfXrefSection[];
  entries: PdfXrefEntry[];
  trailerText: string | null;
  trailer?: PdfTrailer;
}

export interface PdfXrefStream {
  kind: "stream";
  startOffset: number;
  objectNumber: number;
  generation: number;
  trailer: PdfTrailer;
}

export type PdfXref = PdfXrefTable | PdfXrefStream;

export interface PdfInfoDictionary {
  raw: string;
  title: string | null;
  author: string | null;
  subject: string | null;
  keywords: string | null;
  creator: string | null;
  producer: string | null;
  creationDate: string | null;
  modDate: string | null;
}

export interface PdfCatalog {
  raw: string;
  pagesRef: PdfIndirectRef | null;
  namesRef: PdfIndirectRef | null;
  outlinesRef: PdfIndirectRef | null;
}

export interface PdfPages {
  raw: string;
  count: number | null;
}

export interface PdfParseResult {
  size: number;
  header: PdfHeader;
  startxref: number | null;
  xref: PdfXref | null;
  trailer: PdfTrailer | null;
  info: PdfInfoDictionary | null;
  catalog: PdfCatalog | null;
  pages: PdfPages | null;
  issues: string[];
}
