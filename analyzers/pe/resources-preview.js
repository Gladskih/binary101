"use strict";

import { addIconPreview, addGroupIconPreview } from "./resources-preview-icon.js";

function addPreviewIssue(langEntry, message) {
  if (!message) return;
  langEntry.previewIssues = langEntry.previewIssues || [];
  langEntry.previewIssues.push(String(message));
}

function decodeTextResource(data) {
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

function addManifestPreview(langEntry, data, typeName) {
  if (typeName !== "MANIFEST") return;
  const { text, error } = decodeTextResource(data);
  if (error) addPreviewIssue(langEntry, "Manifest text could not be fully decoded.");
  if (!text) return;
  langEntry.previewKind = "text";
  langEntry.textPreview = text;
}

function addHtmlPreview(langEntry, data, typeName) {
  if (typeName !== "HTML") return;
  const { text, error, encoding } = decodeTextResource(data);
  if (error) addPreviewIssue(langEntry, "HTML resource text could not be decoded.");
  if (!text) return;
  langEntry.previewKind = "html";
  langEntry.textPreview = text;
  langEntry.textEncoding = encoding || null;
}

function addStringTablePreview(langEntry, data, typeName, entryId) {
  if (typeName !== "STRING") return;
  if (data.length < 2) {
    addPreviewIssue(langEntry, "String table is too small to read.");
    return;
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const entries = [];
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
  langEntry.stringTable = entries;
}

function addMessageTablePreview(langEntry, data, typeName) {
  if (typeName !== "MESSAGETABLE") return;
  if (data.length < 4) {
    addPreviewIssue(langEntry, "Message table header is incomplete.");
    return;
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const blockCount = dv.getUint32(0, true);
  if (!blockCount || 4 + blockCount * 12 > data.length) {
    addPreviewIssue(langEntry, "Message table block list is invalid.");
    return;
  }
  const messages = [];
  const maxMessages = 12;
  let truncated = false;
  for (let blockIndex = 0; blockIndex < blockCount; blockIndex++) {
    const base = 4 + blockIndex * 12;
    const lowId = dv.getUint32(base + 0, true);
    const highId = dv.getUint32(base + 4, true);
    const offset = dv.getUint32(base + 8, true);
    if (offset >= data.length) {
      addPreviewIssue(langEntry, `Message block ${blockIndex} offset is outside resource.`);
      continue;
    }
    const limit = data.length;
    let cursor = offset;
    let currentId = lowId;
    while (cursor + 4 <= limit && currentId <= highId) {
      const length = dv.getUint16(cursor + 0, true);
      const flags = dv.getUint16(cursor + 2, true);
      if (length < 4 || cursor + length > limit) {
        addPreviewIssue(langEntry, "Message entry truncated or invalid length.");
        break;
      }
      const textBytes = data.subarray(cursor + 4, cursor + length);
      const unicode = (flags & 0x0001) !== 0;
      let text = "";
      try {
        if (unicode) {
          text = new TextDecoder("utf-16le", { fatal: false }).decode(textBytes);
        } else {
          text = new TextDecoder("windows-1252", { fatal: false }).decode(textBytes);
        }
      } catch {
        text = "";
        addPreviewIssue(langEntry, "Message text could not be decoded.");
      }
      if (text) {
        messages.push({ id: currentId, text: text.replace(/\u0000+$/, "") });
      }
      cursor += length;
      currentId++;
      if (messages.length >= maxMessages) {
        truncated = true;
        break;
      }
    }
    if (truncated) break;
  }
  if (!messages.length) {
    addPreviewIssue(langEntry, "No message strings were found.");
    return;
  }
  langEntry.previewKind = "messageTable";
  langEntry.messageTable = { messages, truncated };
}

function addVersionPreview(langEntry, data, typeName) {
  if (typeName !== "VERSION") return;
  if (data.length < 0x40 || data.length > 64 * 1024) return;
  const buf = data;
  const dvv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const readUtf16z = offset => {
    let result = "";
    for (let pos = offset; pos + 1 < buf.length; pos += 2) {
      const ch = dvv.getUint16(pos, true);
      if (ch === 0) break;
      result += String.fromCharCode(ch);
    }
    return result;
  };
  const length = dvv.getUint16(0, true);
  const valueLength = dvv.getUint16(2, true);
  const type = dvv.getUint16(4, true);
  const key = readUtf16z(6);
  const valueStart = (6 + key.length * 2 + 2 + 3) & ~3;
  let fixed = null;
  if (key === "VS_VERSION_INFO" && valueLength >= 52 && valueStart + 52 <= buf.length) {
    const v0 = dvv.getUint32(valueStart + 0, true);
    const v1 = dvv.getUint32(valueStart + 4, true);
    const v2 = dvv.getUint32(valueStart + 8, true);
    const v3 = dvv.getUint32(valueStart + 12, true);
    const parsePair = v => ({
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
    length,
    valueLength,
    type,
    key,
    fixed
  };
}

export async function enrichResourcePreviews(file, tree) {
  const { base, limitEnd, top, detail, view, rvaToOff } = tree;
  const isInside = off => off >= base && off < limitEnd;

  const iconIndex = new Map();
  const rootDirView = await view(base, 16);
  const NamedRoot = rootDirView.getUint16(12, true);
  const IdsRoot = rootDirView.getUint16(14, true);
  const countRoot = NamedRoot + IdsRoot;
  for (let index = 0; index < countRoot; index++) {
    const e = await view(base + 16 + index * 8, 8);
    const Name = e.getUint32(0, true);
    const OffsetToData = e.getUint32(4, true);
    const subdir = (OffsetToData & 0x80000000) !== 0;
    const id = (Name & 0x80000000) ? null : (Name & 0xffff);
    if (id !== 3 || !subdir) continue;
    const nameDirRel = OffsetToData & 0x7fffffff;
    const nameDirOff = base + nameDirRel;
    if (!isInside(nameDirOff + 16)) continue;
    const nameDirView = await view(nameDirOff, 16);
    const Named = nameDirView.getUint16(12, true);
    const Ids = nameDirView.getUint16(14, true);
    const count = Named + Ids;
    for (let idx = 0; idx < count; idx++) {
      const e2 = await view(nameDirOff + 16 + idx * 8, 8);
      const Name2 = e2.getUint32(0, true);
      const OffsetToData2 = e2.getUint32(4, true);
      const subdir2 = (OffsetToData2 & 0x80000000) !== 0;
      const id2 = (Name2 & 0x80000000) ? null : (Name2 & 0xffff);
      if (!subdir2) continue;
      const langDirRel = OffsetToData2 & 0x7fffffff;
      const langDirOff = base + langDirRel;
      if (!isInside(langDirOff + 16)) continue;
      const langDirView = await view(langDirOff, 16);
      const NamedL = langDirView.getUint16(12, true);
      const IdsL = langDirView.getUint16(14, true);
      const countL = NamedL + IdsL;
      for (let j = 0; j < countL; j++) {
        const le = await view(langDirOff + 16 + j * 8, 8);
        const NameL = le.getUint32(0, true);
        const OffsetToDataL = le.getUint32(4, true);
        const subdirL = (OffsetToDataL & 0x80000000) !== 0;
        if (subdirL) continue;
        const dataRel = OffsetToDataL & 0x7fffffff;
        const deo2 = base + dataRel;
        if (!isInside(deo2 + 16)) continue;
        const dv2 = await view(deo2, 16);
        const rva2 = dv2.getUint32(0, true);
        const sz2 = dv2.getUint32(4, true);
        if (id2 != null) iconIndex.set(id2, { rva: rva2, size: sz2 });
        break;
      }
    }
  }

  for (const group of detail) {
    const typeName = group.typeName;
    for (const entry of group.entries) {
      for (const langEntry of entry.langs) {
        if (!langEntry.size || !langEntry.dataRVA) continue;
        try {
          const dataOff = rvaToOff(langEntry.dataRVA);
          if (dataOff == null || langEntry.size <= 0) continue;
          const data = new Uint8Array(
            await file.slice(dataOff, dataOff + Math.min(langEntry.size, 262144)).arrayBuffer()
          );
          const safePreview = fn => {
            try {
              fn();
            } catch (err) {
              addPreviewIssue(langEntry, `Preview failed: ${err?.message || err}`);
            }
          };
          safePreview(() => addIconPreview(langEntry, data, typeName));
          safePreview(() => addManifestPreview(langEntry, data, typeName));
          safePreview(() => addHtmlPreview(langEntry, data, typeName));
          safePreview(() => addVersionPreview(langEntry, data, typeName));
          safePreview(() => addStringTablePreview(langEntry, data, typeName, entry.id));
          safePreview(() => addMessageTablePreview(langEntry, data, typeName));
          await addGroupIconPreview(
            file,
            langEntry,
            typeName,
            langEntry.dataRVA,
            langEntry.size,
            iconIndex,
            rvaToOff
          ).catch(err => addPreviewIssue(langEntry, `Icon group preview failed: ${err?.message || err}`));
        } catch {
          addPreviewIssue(langEntry, "Resource bytes could not be read for preview.");
        }
      }
    }
  }

  return { top, detail };
}
