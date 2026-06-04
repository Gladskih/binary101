"use strict";

import { decodeTextResource } from "./text.js";
import type {
  ResourceInfEntryPreview,
  ResourceInfPreview,
  ResourceInfSectionPreview,
  ResourcePreviewResult
} from "./types.js";

const parseInfSectionHeader = (line: string): string | null => {
  // Microsoft INF syntax uses [section-name] headers and key=value directives; AddReg
  // sections also contain comma-separated registry entries without "=".
  // Sources:
  // https://learn.microsoft.com/en-us/windows-hardware/drivers/install/general-syntax-rules-for-inf-files
  // https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-addreg-directive
  const match = /^\[([^\]\r\n]+)\]\s*$/u.exec(line);
  return match?.[1]?.trim() || null;
};

const appendInfEntry = (
  section: ResourceInfSectionPreview,
  line: number,
  text: string
): ResourceInfEntryPreview => {
  const separator = text.indexOf("=");
  const entry = separator === -1
    ? { line, kind: "entry" as const, key: null, value: text }
    : {
        line,
        kind: "directive" as const,
        key: text.slice(0, separator).trim(),
        value: text.slice(separator + 1).trim()
      };
  section.entries.push(entry);
  return entry;
};

const parseInfText = (text: string, issues: string[]): ResourceInfPreview => {
  const sections: ResourceInfSectionPreview[] = [];
  let currentSection: ResourceInfSectionPreview | null = null;
  let commentCount = 0;
  let entryCount = 0;
  text.split(/\r\n|\n|\r/u).forEach((rawLine, index) => {
    const line = rawLine.trim();
    if (!line) return;
    if (line.startsWith(";")) {
      commentCount += 1;
      return;
    }
    const sectionName = parseInfSectionHeader(line);
    if (sectionName) {
      currentSection = { name: sectionName, entries: [] };
      sections.push(currentSection);
      return;
    }
    if (line.startsWith("[")) {
      issues.push(`REGINST INF line ${index + 1} has a malformed section header.`);
      return;
    }
    if (!currentSection) {
      issues.push(`REGINST INF line ${index + 1} appears before any section header.`);
      return;
    }
    appendInfEntry(currentSection, index + 1, line);
    entryCount += 1;
  });
  if (!sections.length) issues.push("REGINST resource text contains no INF-style sections.");
  return { sections, commentCount, entryCount };
};

export function addRegInstPreview(
  data: Uint8Array,
  typeName: string,
  codePage: number | undefined
): ResourcePreviewResult | null {
  if (typeName !== "REGINST") return null;
  const issues: string[] = [];
  const { text, error, encoding, terminated } = decodeTextResource(data, codePage);
  if (error) issues.push("REGINST text could not be fully decoded.");
  if (!text) return { issues: issues.length ? issues : ["REGINST resource is empty."] };
  if (terminated) issues.push("REGINST preview stopped at a NUL terminator before the declared data size.");
  const infPreview = parseInfText(text, issues);
  return {
    preview: {
      previewKind: "inf",
      textPreview: text,
      ...(encoding ? { textEncoding: encoding } : {}),
      infPreview,
      previewFields: [
        { label: "Type", value: "REGINST" },
        { label: "Format", value: "INF-style registration script" },
        { label: "Sections", value: String(infPreview.sections.length) },
        { label: "Entries", value: String(infPreview.entryCount) }
      ]
    },
    ...(issues.length ? { issues: [...new Set(issues)] } : {})
  };
}
