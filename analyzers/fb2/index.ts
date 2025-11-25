"use strict";

const MAX_PARSE_BYTES = 1024 * 512;

type NodeWithChildren = Element | Document | null;

interface Fb2Sequence {
  name: string;
  number: string;
}

interface Fb2Languages {
  lang: string;
  srcLang: string;
}

interface Fb2DocumentInfo {
  authors: string[];
  programUsed: string;
  documentId: string;
  documentVersion: string;
  documentDate: string | null;
  sourceUrls: string[];
  sourceOcr: string;
}

interface Fb2PublishInfo {
  publisher: string;
  isbn: string;
  year: string;
  city: string;
}

export interface Fb2ParseResult {
  size: number;
  bytesInspected: number;
  parseError: boolean;
  title: string;
  genres: string[];
  keywords: string[];
  languages: Fb2Languages;
  annotation: string | null;
  sequence: Fb2Sequence | null;
  coverImage: string | null;
  titleAuthors: string[];
  bodyCount: number;
  sectionCount: number;
  binaryCount: number;
  documentInfo: Fb2DocumentInfo;
  publishInfo: Fb2PublishInfo;
}

function firstByTag(parent: NodeWithChildren, tagName: string): Element | null {
  if (!parent) return null;
  const els = parent.getElementsByTagName(tagName);
  return els && els.length ? els.item(0) : null;
}

function allByTag(parent: NodeWithChildren, tagName: string): Element[] {
  if (!parent) return [];
  const els = parent.getElementsByTagName(tagName);
  return els && els.length ? Array.from(els) : [];
}

function textFromElement(parent: NodeWithChildren, tagName: string): string {
  if (!parent) return "";
  const el = firstByTag(parent, tagName);
  if (!el) return "";
  return (el.textContent || "").trim();
}

function collectTexts(parent: NodeWithChildren, tagName: string): string[] {
  return allByTag(parent, tagName)
    .map(el => (el.textContent || "").trim())
    .filter(Boolean);
}

function pickImageHref(imageEl: Element | null): string | null {
  if (!imageEl) return null;
  return (
    imageEl.getAttribute("href") ||
    imageEl.getAttribute("xlink:href") ||
    imageEl.getAttribute("l:href")
  );
}

function formatAuthor(authorEl: Element | null): string | null {
  if (!authorEl) return null;
  const parts = [
    textFromElement(authorEl, "first-name"),
    textFromElement(authorEl, "middle-name"),
    textFromElement(authorEl, "last-name")
  ].filter(Boolean);
  const nick = textFromElement(authorEl, "nickname");
  if (nick) parts.push(`(${nick})`);
  if (!parts.length) return null;
  return parts.join(" ");
}

function collectAuthors(parent: NodeWithChildren, tagName = "author"): string[] {
  return allByTag(parent, tagName).map(formatAuthor).filter(Boolean) as string[];
}

function summarizeAnnotation(titleInfo: Element | null): string | null {
  if (!titleInfo) return null;
  const annotationEl = firstByTag(titleInfo, "annotation");
  if (!annotationEl) return null;
  const text = (annotationEl.textContent || "").trim();
  if (!text) return null;
  const limit = 320;
  return text.length > limit ? `${text.slice(0, limit)}...` : text;
}

function parseSequence(titleInfo: Element | null): Fb2Sequence | null {
  if (!titleInfo) return null;
  const seq = firstByTag(titleInfo, "sequence");
  if (!seq) return null;
  const name = seq.getAttribute("name") || "";
  const number = seq.getAttribute("number") || "";
  if (!name && !number) return null;
  return { name, number };
}

function parseDateWithValue(el: Element | null): string | null {
  if (!el) return null;
  const valueAttr = el.getAttribute("value");
  const text = (el.textContent || "").trim();
  if (valueAttr && text && valueAttr !== text) {
    return `${text} (value=${valueAttr})`;
  }
  return valueAttr || text || null;
}

export async function parseFb2(file: File): Promise<Fb2ParseResult | null> {
  const readBytes = Math.min(file.size || 0, MAX_PARSE_BYTES);
  const buffer = await file.slice(0, readBytes).arrayBuffer();
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const text = decoder.decode(buffer);
  const lower = text.toLowerCase();
  if (!lower.includes("<fictionbook")) return null;

  const parser = new DOMParser();
  const doc = parser.parseFromString(text, "application/xml");
  const parseError = doc.querySelector("parsererror");

  // Root tag is typically written as <FictionBook>, so match both cases
  // to avoid rejecting valid documents due to case sensitivity in XML.
  const root =
    doc.getElementsByTagName("FictionBook")[0] ||
    doc.getElementsByTagName("fictionbook")[0];
  if (!root) return null;

  const description = firstByTag(root, "description");
  const titleInfo = firstByTag(description, "title-info");
  const documentInfo = firstByTag(description, "document-info");
  const publishInfo = firstByTag(description, "publish-info");

  const title = textFromElement(titleInfo, "book-title");
  const genres = collectTexts(titleInfo, "genre");
  const keywords = collectTexts(titleInfo, "keywords");
  const languages: Fb2Languages = {
    lang: textFromElement(titleInfo, "lang"),
    srcLang: textFromElement(titleInfo, "src-lang")
  };
  const annotation = summarizeAnnotation(titleInfo);
  const sequence = parseSequence(titleInfo);
  const titleAuthors = collectAuthors(titleInfo);
  const coverImage = pickImageHref(firstByTag(firstByTag(titleInfo, "coverpage"), "image"));

  const documentAuthors = collectAuthors(documentInfo);
  const programUsed = textFromElement(documentInfo, "program-used");
  const documentId = textFromElement(documentInfo, "id");
  const documentVersion = textFromElement(documentInfo, "version");
  const sourceUrls = collectTexts(documentInfo, "src-url");
  const sourceOcr = textFromElement(documentInfo, "src-ocr");
  const documentDate = parseDateWithValue(firstByTag(documentInfo, "date"));

  const publisher = textFromElement(publishInfo, "publisher");
  const isbn = textFromElement(publishInfo, "isbn");
  const year = textFromElement(publishInfo, "year");
  const city = textFromElement(publishInfo, "city");

  const bodyCount = allByTag(root, "body").length;
  const sectionCount = allByTag(root, "section").length;
  const binaryCount = allByTag(root, "binary").length;

  return {
    size: file.size || 0,
    bytesInspected: readBytes,
    parseError: Boolean(parseError),
    title,
    genres,
    keywords,
    languages,
    annotation,
    sequence,
    coverImage,
    titleAuthors,
    bodyCount,
    sectionCount,
    binaryCount,
    documentInfo: {
      authors: documentAuthors,
      programUsed,
      documentId,
      documentVersion,
      documentDate,
      sourceUrls,
      sourceOcr
    },
    publishInfo: { publisher, isbn, year, city }
  };
}
