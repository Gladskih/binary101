"use strict";
import type { PdfHeader } from "./types.js";

const parseHeader = (text: string, issues: string[]): PdfHeader => {
  const firstLineEnd = text.indexOf("\n");
  const headerLine =
    firstLineEnd !== -1 ? text.slice(0, firstLineEnd).trimEnd() : text.trimEnd();
  const match = headerLine.match(/^%PDF-([0-9]+\.[0-9]+)/);
  if (!match) {
    issues.push("Missing or malformed %PDF- header.");
    return { headerLine, version: null };
  }
  const binaryMarker = text.slice(0, 256).match(/%[^\n]{4,}/);
  const version = match[1] || null;
  const marker = binaryMarker?.[0] ?? null;
  return { headerLine, version, binaryMarker: marker };
};

const parseStartxref = (text: string, issues: string[]): number | null => {
  const idx = text.lastIndexOf("startxref");
  if (idx === -1) {
    issues.push("startxref marker not found.");
    return null;
  }
  const tail = text.slice(idx);
  const match = tail.match(/startxref\s+([0-9]+)/);
  if (!match) {
    issues.push("startxref present but offset is unreadable.");
    return null;
  }
  const offsetText = match[1];
  if (!offsetText) {
    issues.push("startxref present but offset text is missing.");
    return null;
  }
  return Number.parseInt(offsetText, 10);
};

export { parseHeader, parseStartxref };
