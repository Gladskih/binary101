"use strict";

import { addIconPreview, addGroupIconPreview } from "./resources-preview-icon.js";

function addManifestPreview(langEntry, data, typeName) {
  if (typeName !== "MANIFEST") return;
  if (!data.length) return;
  let text = "";
  if (data.length >= 2 && data[0] === 0xff && data[1] === 0xfe) {
    for (let index = 2; index + 1 < data.length; index += 2) {
      const ch = data[index] | (data[index + 1] << 8);
      if (ch === 0) break;
      text += String.fromCharCode(ch);
    }
  } else {
    try {
      text = new TextDecoder("utf-8").decode(data);
    } catch {
      text = "";
    }
  }
  if (!text) return;
  langEntry.previewKind = "text";
  langEntry.textPreview = text;
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
          if (!isInside(dataOff) || !isInside(dataOff + 1)) {
            const data = new Uint8Array(await file.slice(dataOff, dataOff + Math.min(langEntry.size, 262144)).arrayBuffer());
            addIconPreview(langEntry, data, typeName);
            addManifestPreview(langEntry, data, typeName);
            addVersionPreview(langEntry, data, typeName);
            await addGroupIconPreview(file, langEntry, typeName, langEntry.dataRVA, langEntry.size, iconIndex, rvaToOff);
          } else {
            const data = new Uint8Array(await file.slice(dataOff, dataOff + Math.min(langEntry.size, 262144)).arrayBuffer());
            addIconPreview(langEntry, data, typeName);
            addManifestPreview(langEntry, data, typeName);
            addVersionPreview(langEntry, data, typeName);
            await addGroupIconPreview(file, langEntry, typeName, langEntry.dataRVA, langEntry.size, iconIndex, rvaToOff);
          }
        } catch {
          // best-effort previews
        }
      }
    }
  }

  return { top, detail };
}
