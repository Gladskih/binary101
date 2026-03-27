"use strict";

import type { ResourcePreviewResult } from "./types.js";

const decodeUtf16leText = (
  data: Uint8Array
): { text: string; encoding: string; terminated: boolean } => {
  let end = data.length - (data.length % 2);
  let terminated = false;
  const view = new DataView(data.buffer, data.byteOffset, end);
  for (let index = 0; index + Uint16Array.BYTES_PER_ELEMENT <= end; index += 2) {
    const codeUnit = view.getUint16(index, true);
    if (codeUnit === 0) {
      end = index;
      terminated = true;
      break;
    }
  }
  return {
    text: new TextDecoder("utf-16le", { fatal: false }).decode(data.subarray(0, end)),
    encoding: "UTF-16LE",
    terminated
  };
};

const decodeUtf8Text = (data: Uint8Array): { text: string; encoding: string; terminated: boolean } => {
  const terminator = data.indexOf(0);
  const end = terminator === -1 ? data.length : terminator;
  return {
    text: new TextDecoder("utf-8", { fatal: false }).decode(data.subarray(0, end)),
    encoding: "UTF-8",
    terminated: terminator !== -1
  };
};

export function decodeTextResource(
  data: Uint8Array,
  codePage: number | undefined
): { text: string; encoding: string; terminated: boolean; error?: unknown } {
  if (!data?.length) return { text: "", encoding: "", terminated: false };
  if (data.length >= 2) {
    const bom0 = data[0];
    const bom1 = data[1];
    // UTF-16LE BOM bytes. Source:
    // Unicode FAQ / UTF-16, UTF-8, and BOM / https://www.unicode.org/faq/utf_bom.html
    if (bom0 !== undefined && bom1 !== undefined && bom0 === 0xff && bom1 === 0xfe) {
      return decodeUtf16leText(data.subarray(2));
    }
  }
  // Windows code page 1200 identifies UTF-16LE.
  if (codePage === 1200) {
    return decodeUtf16leText(data);
  }
  try {
    // Windows code page 20127 identifies US-ASCII.
    if (codePage === 20127) {
      const decoded = new TextDecoder("us-ascii", { fatal: false }).decode(
        data.subarray(0, data.indexOf(0) === -1 ? data.length : data.indexOf(0))
      );
      return { text: decoded, encoding: "US-ASCII", terminated: data.indexOf(0) !== -1 };
    }
    const decoded = decodeUtf8Text(data);
    return decoded;
  } catch (err) {
    return { text: "", encoding: "", terminated: false, error: err };
  }
}

export function addManifestPreview(
  data: Uint8Array,
  typeName: string,
  codePage: number | undefined
): ResourcePreviewResult | null {
  if (typeName !== "MANIFEST") return null;
  const issues: string[] = [];
  const { text, error, terminated } = decodeTextResource(data, codePage);
  if (error) issues.push("Manifest text could not be fully decoded.");
  if (!text) return issues.length ? { issues } : null;
  if (terminated) issues.push("Manifest preview stopped at a NUL terminator before the declared data size.");
  return {
    preview: {
      previewKind: "text",
      textPreview: text,
      previewFields: [{ label: "Type", value: "MANIFEST" }]
    },
    ...(issues.length ? { issues } : {})
  };
}

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

export function addStringTablePreview(
  data: Uint8Array,
  typeName: string,
  entryId: number | null
): ResourcePreviewResult | null {
  const utf16Decoder = new TextDecoder("utf-16le", { fatal: false });
  if (typeName !== "STRING") return null;
  if (data.length < 2) {
    return { issues: ["String table is too small to read."] };
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const entries: Array<{ id: number | null; text: string }> = [];
  const issues: string[] = [];
  let offset = 0;
  // String-table block IDs are 1-based; each block covers exactly 16 string IDs. Source:
  // Microsoft Learn, STRINGTABLE resource / LoadString.
  const baseId = entryId != null ? Math.max(0, entryId - 1) * 16 : null;
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
  if (!entries.length) {
    return { issues: [...issues, "No strings could be read from table."] };
  }
  return {
    preview: {
      previewKind: "stringTable",
      stringTable: entries
    },
    ...(issues.length ? { issues } : {})
  };
}
