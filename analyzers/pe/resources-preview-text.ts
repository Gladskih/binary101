"use strict";

import type { ResourceLangWithPreview } from "./resources-preview-types.js";

export function addPreviewIssue(langEntry: ResourceLangWithPreview, message: unknown): void {
  if (!message) return;
  langEntry.previewIssues = langEntry.previewIssues || [];
  langEntry.previewIssues.push(String(message));
}

function decodeTextResource(
  data: Uint8Array
): { text: string; encoding: string; error?: unknown } {
  if (!data?.length) return { text: "", encoding: "" };
  if (data.length >= 2 && data[0] === 0xff && data[1] === 0xfe) {
    let text = "";
    for (let index = 2; index + 1 < data.length; index += 2) {
      const ch = data[index] | (data[index + 1] << 8);
      if (ch === 0) break;
      text += String.fromCharCode(ch);
    }
    return { text, encoding: "UTF-16LE" };
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(data);
    return { text, encoding: "UTF-8" };
  } catch (err) {
    return { text: "", encoding: "", error: err };
  }
}

export function addManifestPreview(
  langEntry: ResourceLangWithPreview,
  data: Uint8Array,
  typeName: string
): void {
  if (typeName !== "MANIFEST") return;
  const { text, error } = decodeTextResource(data);
  if (error) addPreviewIssue(langEntry, "Manifest text could not be fully decoded.");
  if (!text) return;
  langEntry.previewKind = "text";
  langEntry.textPreview = text;
}

export function addHtmlPreview(
  langEntry: ResourceLangWithPreview,
  data: Uint8Array,
  typeName: string
): void {
  if (typeName !== "HTML") return;
  const { text, error, encoding } = decodeTextResource(data);
  if (error) addPreviewIssue(langEntry, "HTML resource text could not be decoded.");
  if (!text) return;
  langEntry.previewKind = "html";
  langEntry.textPreview = text;
  langEntry.textEncoding = encoding || null;
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
  while (offset + 2 <= data.length && entries.length < 32) {
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

export function addMessageTablePreview(
  langEntry: ResourceLangWithPreview,
  data: Uint8Array,
  typeName: string
): void {
  if (typeName !== "MESSAGETABLE") return;
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const messageCount = Math.min(16, Math.floor(data.length / 24));
  const messages: Array<{ id: number; strings: string[] }> = [];
  for (let index = 0; index < messageCount; index += 1) {
    const id = dv.getUint32(index * 24 + 0, true);
    const count = dv.getUint16(index * 24 + 4, true);
    const entryRva = dv.getUint32(index * 24 + 8, true);
    const entrySize = dv.getUint32(index * 24 + 12, true);
    const entryStart = entryRva - data.byteOffset;
    if (entryStart < 0 || entryStart + entrySize > data.length) break;
    const entryBytes = new Uint8Array(data.buffer, data.byteOffset + entryStart, entrySize);
    const texts: string[] = [];
    let pos = 0;
    for (let s = 0; s < count && pos + 4 <= entryBytes.length; s += 1) {
      const len = entryBytes[pos] | (entryBytes[pos + 1] << 8);
      const flags = entryBytes[pos + 2] | (entryBytes[pos + 3] << 8);
      const isUnicode = (flags & 0x0001) !== 0;
      pos += 4;
      if (pos + len > entryBytes.length) break;
      let str = "";
      if (isUnicode) {
        for (let chPos = 0; chPos + 1 < len; chPos += 2) {
          const code = entryBytes[pos + chPos] | (entryBytes[pos + chPos + 1] << 8);
          str += String.fromCharCode(code);
        }
      } else {
        str = new TextDecoder("utf-8", { fatal: false }).decode(
          entryBytes.subarray(pos, pos + len).filter(b => b !== 0)
        );
      }
      texts.push(str.trim());
      pos += len;
    }
    messages.push({ id, strings: texts });
  }
  if (messages.length) {
    langEntry.previewKind = "messageTable";
    langEntry.messageItems = messages;
    langEntry.messageTable = { messages, truncated: false };
  }
}

export function addVersionPreview(
  langEntry: ResourceLangWithPreview,
  data: Uint8Array,
  typeName: string
): void {
  if (typeName !== "VERSION") return;
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (dv.byteLength < 6) return;
  const len = dv.getUint16(0, true);
  const valueLength = dv.getUint16(2, true);
  const type = dv.getUint16(4, true);
  const key = String.fromCharCode(...new Uint8Array(data.buffer, data.byteOffset + 6, Math.max(0, data.length - 6)))
    .split("\0")[0]
    .trim();
  let valueStart = 6 + (key.length + 2 + (key.length % 2 === 0 ? 0 : 1));
  valueStart = (valueStart + 3) & ~3;
  let fixed = null;
  if (valueLength >= 52 && valueStart + 52 <= data.length) {
    const dvv = new DataView(data.buffer, data.byteOffset + valueStart, Math.min(52, dv.byteLength - valueStart));
    const v0 = dvv.getUint32(0, true);
    const v1 = dvv.getUint32(4, true);
    const v2 = dvv.getUint32(8, true);
    const v3 = dvv.getUint32(12, true);
    const parsePair = (v: number) => ({
      major: (v >>> 16) & 0xffff,
      minor: v & 0xffff
    });
    const fileVer = { high: parsePair(v0), low: parsePair(v1) };
    const prodVer = { high: parsePair(v2), low: parsePair(v3) };
    fixed = {
      fileVersion: fileVer,
      productVersion: prodVer,
      fileVersionString: `${fileVer.high.major}.${fileVer.high.minor}.${fileVer.low.major}.${fileVer.low.minor}`,
      productVersionString: `${prodVer.high.major}.${prodVer.high.minor}.${prodVer.low.major}.${prodVer.low.minor}`
    };
  }
  langEntry.previewKind = "version";
  langEntry.versionInfo = {
    length: len,
    valueLength,
    type,
    key,
    fixed
  };
}
