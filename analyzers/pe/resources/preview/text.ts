"use strict";

import type { ResourcePreviewResult } from "./types.js";

// Windows identifiers mapped to WHATWG Encoding labels, not arbitrary decoder names.
// https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
// https://encoding.spec.whatwg.org/#names-and-labels
const codePageLabels = new Map<number, string>([
  [65001, "UTF-8"], [1200, "UTF-16LE"], [1201, "UTF-16BE"], [20127, "US-ASCII"],
  [874, "windows-874"], [932, "shift_jis"], [936, "gbk"], [949, "euc-kr"], [950, "big5"],
  ...Array.from({ length: 9 }, (_, index): [number, string] =>
    [1250 + index, `windows-${1250 + index}`])
]);

const bomEncoding = (data: Uint8Array): string | null => {
  // BOM takes precedence over PE metadata (Unicode FAQ, UTF BOM).
  if (data[0] === 0xff && data[1] === 0xfe) return "UTF-16LE";
  if (data[0] === 0xfe && data[1] === 0xff) return "UTF-16BE";
  if (data[0] === 0xef && data[1] === 0xbb && data[2] === 0xbf) return "UTF-8";
  return null;
};

const codePageIssue = (bom: string | null, codePage: number | undefined): Error | undefined =>
  !bom && codePage && !codePageLabels.has(codePage)
    ? new Error(`Unsupported code page ${codePage}; UTF-8 fallback is uncertain.`) : undefined;

export function decodeTextResource(
  data: Uint8Array,
  codePage: number | undefined
): { text: string; encoding: string; terminated: boolean; error?: unknown } {
  if (!data.length) return { text: "", encoding: "", terminated: false };
  const bom = bomEncoding(data);
  const encoding = bom ?? codePageLabels.get(codePage ?? 0) ?? "UTF-8";
  const end = findTextEnd(data, encoding);
  try {
    const bytes = data.subarray(0, end);
    if (encoding === "US-ASCII" && bytes.some(byte => byte >= 128)) {
      throw new Error("Declared US-ASCII text contains non-ASCII bytes.");
    }
    const text = new TextDecoder(encoding, { fatal: true }).decode(bytes);
    const error = codePageIssue(bom, codePage);
    return { text, encoding, terminated: end < data.length, ...(error ? { error } : {}) };
  } catch (err) {
    return { text: "", encoding, terminated: end < data.length, error: err };
  }
}

const findTextEnd = (data: Uint8Array, encoding: string): number => {
  if (!encoding.startsWith("UTF-16")) {
    const end = data.indexOf(0);
    return end < 0 ? data.length : end;
  }
  for (let index = 0; index + 1 < data.length; index += 2) {
    if (data[index] === 0 && data[index + 1] === 0) return index;
  }
  return data.length;
};

const looksLikeHtmlText = (text: string): boolean => /^\s*</u.test(text);

export function addHtmlPreview(
  data: Uint8Array,
  typeName: string,
  codePage: number | undefined
): ResourcePreviewResult | null {
  if (typeName !== "HTML") return null;
  const issues: string[] = [];
  const { text, error, encoding, terminated } = decodeTextResource(data, codePage);
  if (error) issues.push("HTML resource text could not be decoded.");
  if (!text) return issues.length ? { issues } : null;
  if (!looksLikeHtmlText(text)) return null;
  if (terminated) issues.push("HTML preview stopped at a NUL terminator before the declared data size.");
  return {
    preview: {
      previewKind: "html",
      textPreview: text,
      textEncoding: encoding || null,
      previewFields: [
        { label: "Type", value: "HTML" },
        { label: "Safety", value: "Shown as escaped source; HTML is not executed." }
      ]
    },
    ...(issues.length ? { issues } : {})
  };
}

const readStringBlock = (data: Uint8Array, dv: DataView,
  entries: Array<{ id: number | null; text: string }>, baseId: number | null, issues: string[]): number => {
  const utf16Decoder = new TextDecoder("utf-16le", { fatal: false });
  let offset = 0;
  while (offset + 2 <= data.length && entries.length < 16) {
    const len = dv.getUint16(offset, true);
    offset += 2;
    const byteLen = len * 2;
    if (offset + byteLen > data.length) {
      issues.push("String table data ended unexpectedly.");
      break;
    }
    const text = utf16Decoder.decode(data.subarray(offset, offset + byteLen));
    const id = baseId != null ? baseId + entries.length : null;
    entries.push({ id, text });
    offset += byteLen;
  }
  return offset;
};

export function addStringTablePreview(
  data: Uint8Array,
  typeName: string,
  entryId: number | null
): ResourcePreviewResult | null {
  if (typeName !== "STRING") return null;
  if (data.length < 2) {
    return { issues: ["String table is too small to read."] };
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const entries: Array<{ id: number | null; text: string }> = [];
  const issues: string[] = [];
  // String-table block IDs are 1-based; each block covers exactly 16 string IDs. Source:
  // Microsoft Learn, STRINGTABLE resource / LoadString.
  const baseId = entryId != null ? Math.max(0, entryId - 1) * 16 : null;
  const offset = readStringBlock(data, dv, entries, baseId, issues);
  if (!entries.length) {
    return { issues: [...issues, "No strings could be read from table."] };
  }
  if (entries.length < 16) issues.push("String table block contains fewer than 16 entries.");
  if (entries.length === 16 && offset < data.length) issues.push("String table has trailing bytes.");
  return {
    preview: {
      previewKind: "stringTable",
      stringTable: entries
    },
    ...(issues.length ? { issues } : {})
  };
}
