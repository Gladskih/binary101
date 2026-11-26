export interface PdfIndirectRef {
  objectNumber: number;
  generation: number;
}

export interface PdfHeader {
  headerLine: string;
  version: string | null;
  binaryMarker?: string | null;
}

export type PdfXrefEntry = { objectNumber: number } & (
  { kind: "free"; nextFree: number; generation: number } |
  { kind: "direct"; offset: number; generation: number } |
  { kind: "compressed"; streamObject: number; index: number } |
  { kind: "unknown"; type: number; second: number; third: number }
);

export interface PdfXrefSection {
  start: number;
  count: number;
}

export interface PdfTrailer {
  raw: string;
  fields: PdfDictionaryField[];
  size: number | null;
  rootRef: PdfIndirectRef | null;
  infoRef: PdfIndirectRef | null;
  id: [string, string] | null;
  prev: number | null;
  xrefStreamOffset: number | null;
  encrypt: string | null;
}

export type PdfXref = {
  offset: number;
  sections: PdfXrefSection[];
  entries: PdfXrefEntry[] | null;
  trailer: PdfTrailer | null;
} & ({ kind: "table" } | { kind: "stream"; object: PdfIndirectRef });

export interface PdfRevision {
  primary: PdfXref;
  supplement?: PdfXref;
}

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
  fields: PdfDictionaryField[];
  pagesRef: PdfIndirectRef | null;
  namesRef: PdfIndirectRef | null;
  outlinesRef: PdfIndirectRef | null;
}

export interface PdfDictionaryField {
  key: string;
  value: string;
}

export interface PdfPages {
  raw: string;
  count: number | null;
  entries: PdfPage[];
}

export type PdfRectangle = [number, number, number, number];

export interface PdfPage {
  ref: PdfIndirectRef;
  mediaBox: PdfRectangle | null;
  cropBox: PdfRectangle | null;
  rotation: number | null;
  userUnit: number | null;
}

export interface PdfEmbeddedFile {
  fileSpec: PdfIndirectRef | null;
  stream: PdfIndirectRef;
  name: string | null;
  description: string | null;
  mediaType: string | null;
  decodedSize: number | null;
  storedSize: number | null;
  relationship: string | null;
  sources: string[];
}

export interface PdfParseResult {
  size: number;
  header: PdfHeader;
  startxref: number | null;
  revisions: PdfRevision[];
  info: PdfInfoDictionary | null;
  catalog: PdfCatalog | null;
  pages: PdfPages | null;
  embeddedFiles: PdfEmbeddedFile[];
  issues: string[];
}
