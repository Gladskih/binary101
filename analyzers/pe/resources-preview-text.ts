"use strict";

import type { ResourceLangWithPreview } from "./resources-preview-types.js";

export function addPreviewIssue(langEntry: ResourceLangWithPreview, message: unknown): void {
  if (!message) return;
  langEntry.previewIssues = langEntry.previewIssues || [];
  langEntry.previewIssues.push(String(message));
}

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

function decodeTextResource(
  data: Uint8Array,
  codePage: number | undefined
): { text: string; encoding: string; terminated: boolean; error?: unknown } {
  if (!data?.length) return { text: "", encoding: "", terminated: false };
  if (data.length >= 2) {
    const bom0 = data[0];
    const bom1 = data[1];
    if (bom0 !== undefined && bom1 !== undefined && bom0 === 0xff && bom1 === 0xfe) {
      return decodeUtf16leText(data.subarray(2));
    }
  }
  if (codePage === 1200) {
    return decodeUtf16leText(data);
  }
  try {
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
  langEntry: ResourceLangWithPreview,
  data: Uint8Array,
  typeName: string,
  codePage: number | undefined
): void {
  if (typeName !== "MANIFEST") return;
  const { text, error, terminated } = decodeTextResource(data, codePage);
  if (error) addPreviewIssue(langEntry, "Manifest text could not be fully decoded.");
  if (!text) return;
  langEntry.previewKind = "text";
  langEntry.textPreview = text;
  if (terminated) {
    addPreviewIssue(langEntry, "Manifest preview stopped at a NUL terminator before the declared data size.");
  }
}

export function addHtmlPreview(
  langEntry: ResourceLangWithPreview,
  data: Uint8Array,
  typeName: string,
  codePage: number | undefined
): void {
  if (typeName !== "HTML") return;
  const { text, error, encoding, terminated } = decodeTextResource(data, codePage);
  if (error) addPreviewIssue(langEntry, "HTML resource text could not be decoded.");
  if (!text) return;
  langEntry.previewKind = "html";
  langEntry.textPreview = text;
  langEntry.textEncoding = encoding || null;
  if (terminated) {
    addPreviewIssue(langEntry, "HTML preview stopped at a NUL terminator before the declared data size.");
  }
}

export function addStringTablePreview(
  langEntry: ResourceLangWithPreview,
  data: Uint8Array,
  typeName: string,
  entryId: number | null
): void {
  if (typeName !== "STRING") return;
  if (data.length < 2) {
    addPreviewIssue(langEntry, "String table is too small to read.");
    return;
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const entries: Array<{ id: number | null; text: string }> = [];
  let offset = 0;
  const baseId = entryId != null ? Math.max(0, entryId - 1) * 16 : null;
  // Win32 STRINGTABLE blocks contain exactly 16 UTF-16 entries.
  while (offset + 2 <= data.length && entries.length < 16) {
    const len = dv.getUint16(offset, true);
    offset += 2;
    const byteLen = len * 2;
    if (offset + byteLen > data.length) {
      addPreviewIssue(langEntry, "String table data ended unexpectedly.");
      break;
    }
    let text = "";
    for (let pos = 0; pos + 1 < byteLen; pos += 2) {
      const ch = dv.getUint16(offset + pos, true);
      if (ch === 0) break;
      text += String.fromCharCode(ch);
    }
    const id = baseId != null ? baseId + entries.length : null;
    entries.push({ id, text });
    offset += byteLen;
  }
  if (!entries.length) {
    addPreviewIssue(langEntry, "No strings could be read from table.");
    return;
  }
  langEntry.previewKind = "stringTable";
  langEntry.stringPreview = entries;
  langEntry.stringTable = entries;
}

export function addVersionPreview(
  langEntry: ResourceLangWithPreview,
  data: Uint8Array,
  typeName: string
): void {
  if (typeName !== "VERSION") return;
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const headerSize = 6; // VS_VERSIONINFO header: wLength(2) + wValueLength(2) + wType(2)
  const dwordAlign = 4;
  // VS_FIXEDFILEINFO is 13 DWORDs.
  const fixedMinSize = 13 * Uint32Array.BYTES_PER_ELEMENT;
  if (dv.byteLength < headerSize) return;
  const len = dv.getUint16(0, true);
  const valueLength = dv.getUint16(2, true);
  let keyBytes = 0;
  const keyLimit = Math.min(len, dv.byteLength);
  const expectedKey = "VS_VERSION_INFO";
  let pos = headerSize;
  let validKey = true;
  for (let idx = 0; idx < expectedKey.length; idx += 1) {
    if (pos + 1 >= keyLimit) {
      validKey = false;
      break;
    }
    const code = dv.getUint16(pos, true);
    keyBytes += 2;
    if (code !== expectedKey.charCodeAt(idx)) {
      validKey = false;
      break;
    }
    pos += 2;
  }
  if (validKey) {
    if (pos + 1 < keyLimit) {
      const terminator = dv.getUint16(pos, true);
      keyBytes += 2;
      if (terminator !== 0) validKey = false;
    } else {
      validKey = false;
    }
  }
  if (!validKey) {
    addPreviewIssue(langEntry, "VERSION resource key is missing or invalid.");
    return;
  }
  // Align start of VS_FIXEDFILEINFO to DWORD boundary after the UTF-16 key string.
  const valueStart = (headerSize + keyBytes + (dwordAlign - 1)) & ~(dwordAlign - 1);
  const declaredLength = Math.min(len, dv.byteLength);
  if (valueLength < fixedMinSize || valueStart + fixedMinSize > declaredLength) {
    addPreviewIssue(langEntry, "Version block is too small to read VS_FIXEDFILEINFO.");
    return;
  }
  const fixedView = new DataView(
    data.buffer,
    data.byteOffset + valueStart,
    Math.min(valueLength, declaredLength - valueStart)
  );
  const signature = fixedView.getUint32(0, true);
  const structVersion = fixedView.getUint32(4, true);
  if (signature !== 0xfEEF04BD) {
    addPreviewIssue(langEntry, "VS_FIXEDFILEINFO signature is missing or invalid.");
    return;
  }
  if (structVersion !== 0x00010000) {
    addPreviewIssue(langEntry, "VS_FIXEDFILEINFO struct version is unexpected.");
    return;
  }
  if (fixedView.byteLength < fixedMinSize) {
    addPreviewIssue(langEntry, "VS_FIXEDFILEINFO is truncated.");
    return;
  }
  const v0 = fixedView.getUint32(8, true);
  const v1 = fixedView.getUint32(12, true);
  const v2 = fixedView.getUint32(16, true);
  const v3 = fixedView.getUint32(20, true);
  const parsePair = (v: number) => ({
    major: (v >>> 16) & 0xffff,
    minor: v & 0xffff
  });
  const fileVer = { high: parsePair(v0), low: parsePair(v1) };
  const prodVer = { high: parsePair(v2), low: parsePair(v3) };
  langEntry.previewKind = "version";
  langEntry.versionInfo = {
    fileVersionString: `${fileVer.high.major}.${fileVer.high.minor}.${fileVer.low.major}.${fileVer.low.minor}`,
    productVersionString: `${prodVer.high.major}.${prodVer.high.minor}.${prodVer.low.major}.${prodVer.low.minor}`
  };
}
