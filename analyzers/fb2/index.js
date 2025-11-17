"use strict";

const MAX_PARSE_BYTES = 1024 * 512;

function textFromElement(parent, selector) {
  if (!parent) return "";
  const el = parent.querySelector(selector);
  if (!el) return "";
  return (el.textContent || "").trim();
}

function collectTexts(parent, selector) {
  if (!parent) return [];
  return Array.from(parent.querySelectorAll(selector))
    .map(el => (el.textContent || "").trim())
    .filter(Boolean);
}

function pickImageHref(imageEl) {
  if (!imageEl) return null;
  return (
    imageEl.getAttribute("href") ||
    imageEl.getAttribute("xlink:href") ||
    imageEl.getAttribute("l:href")
  );
}

function formatAuthor(authorEl) {
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

function collectAuthors(parent, selector = "author") {
  if (!parent) return [];
  return Array.from(parent.querySelectorAll(selector))
    .map(formatAuthor)
    .filter(Boolean);
}

function summarizeAnnotation(titleInfo) {
  if (!titleInfo) return null;
  const annotationEl = titleInfo.querySelector("annotation");
  if (!annotationEl) return null;
  const text = (annotationEl.textContent || "").trim();
  if (!text) return null;
  const limit = 320;
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}

function parseSequence(titleInfo) {
  if (!titleInfo) return null;
  const seq = titleInfo.querySelector("sequence");
  if (!seq) return null;
  const name = seq.getAttribute("name") || "";
  const number = seq.getAttribute("number") || "";
  if (!name && !number) return null;
  return { name, number };
}

function parseDateWithValue(el) {
  if (!el) return null;
  const valueAttr = el.getAttribute("value");
  const text = (el.textContent || "").trim();
  if (valueAttr && text && valueAttr !== text) {
    return `${text} (value=${valueAttr})`;
  }
  return valueAttr || text || null;
}

export async function parseFb2(file) {
  const readBytes = Math.min(file.size || 0, MAX_PARSE_BYTES);
  const buffer = await file.slice(0, readBytes).arrayBuffer();
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const text = decoder.decode(buffer);
  const lower = text.toLowerCase();
  if (lower.indexOf("<fictionbook") === -1) return null;

  const parser = new DOMParser();
  const doc = parser.parseFromString(text, "application/xml");
  const parseError = doc.querySelector("parsererror");

  // Root tag is typically written as <FictionBook>, so match both cases
  // to avoid rejecting valid documents due to case sensitivity in XML.
  const root = doc.querySelector("fictionbook, FictionBook");
  if (!root) return null;

  const description = root.querySelector("description");
  const titleInfo = description && description.querySelector("title-info");
  const documentInfo = description && description.querySelector("document-info");
  const publishInfo = description && description.querySelector("publish-info");

  const title = textFromElement(titleInfo, "book-title");
  const genres = collectTexts(titleInfo, "genre");
  const keywords = collectTexts(titleInfo, "keywords");
  const languages = {
    lang: textFromElement(titleInfo, "lang"),
    srcLang: textFromElement(titleInfo, "src-lang")
  };
  const annotation = summarizeAnnotation(titleInfo);
  const sequence = parseSequence(titleInfo);
  const titleAuthors = collectAuthors(titleInfo);
  const coverImage = pickImageHref(
    titleInfo && titleInfo.querySelector("coverpage > image")
  );

  const documentAuthors = collectAuthors(documentInfo);
  const programUsed = textFromElement(documentInfo, "program-used");
  const documentId = textFromElement(documentInfo, "id");
  const documentVersion = textFromElement(documentInfo, "version");
  const sourceUrls = collectTexts(documentInfo, "src-url");
  const sourceOcr = textFromElement(documentInfo, "src-ocr");
  const documentDate = parseDateWithValue(
    documentInfo && documentInfo.querySelector("date")
  );

  const publisher = textFromElement(publishInfo, "publisher");
  const isbn = textFromElement(publishInfo, "isbn");
  const year = textFromElement(publishInfo, "year");
  const city = textFromElement(publishInfo, "city");

  const bodyCount = root.querySelectorAll("body").length;
  const sectionCount = root.querySelectorAll("body section").length;
  const binaryCount = root.querySelectorAll("binary").length;

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
