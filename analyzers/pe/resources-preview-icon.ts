// @ts-nocheck
"use strict";

function base64FromU8(u8) {
  let s = "";
  const chunk = 0x8000;
  for (let index = 0; index < u8.length; index += chunk) {
    s += String.fromCharCode(...u8.subarray(index, Math.min(index + chunk, u8.length)));
  }
  try {
    return btoa(s);
  } catch {
    return "";
  }
}

export function addIconPreview(langEntry, data, typeName) {
  if (typeName !== "ICON") return;
  if (data.length < 8) return;
  const isPng =
    data[0] === 0x89 && data[1] === 0x50 && data[2] === 0x4e && data[3] === 0x47 &&
    data[4] === 0x0d && data[5] === 0x0a && data[6] === 0x1a && data[7] === 0x0a;
  if (isPng) {
    langEntry.previewKind = "image";
    langEntry.previewMime = "image/png";
    langEntry.previewDataUrl = `data:image/png;base64,${base64FromU8(data)}`;
    return;
  }
  if (data.length < 40) return;
  const dvb = new DataView(data.buffer, data.byteOffset, Math.min(64, data.length));
  const hdrSize = dvb.getUint32(0, true);
  if (hdrSize !== 40 && hdrSize !== 108 && hdrSize !== 124) return;
  const w = dvb.getInt32(4, true);
  const h2 = dvb.getInt32(8, true);
  const bitCount = dvb.getUint16(14, true);
  const outW = Math.max(1, Math.min(256, Math.abs(w)));
  const outH = Math.max(1, Math.min(256, Math.abs(Math.floor(h2 / 2))));
  const dirSize = 6 + 16;
  const ico = new Uint8Array(dirSize + data.length);
  const dvi = new DataView(ico.buffer);
  dvi.setUint16(0, 0, true);
  dvi.setUint16(2, 1, true);
  dvi.setUint16(4, 1, true);
  dvi.setUint8(6, outW === 256 ? 0 : outW);
  dvi.setUint8(7, outH === 256 ? 0 : outH);
  dvi.setUint8(8, 0);
  dvi.setUint8(9, 0);
  dvi.setUint16(10, 1, true);
  dvi.setUint16(12, bitCount, true);
  dvi.setUint32(14, data.length >>> 0, true);
  dvi.setUint32(18, dirSize >>> 0, true);
  ico.set(data, dirSize);
  langEntry.previewKind = "image";
  langEntry.previewMime = "image/x-icon";
  langEntry.previewDataUrl = `data:image/x-icon;base64,${base64FromU8(ico)}`;
}

export async function addGroupIconPreview(file, langEntry, typeName, dataRva, size, iconIndex, rvaToOff) {
  if (typeName !== "GROUP_ICON") return;
  const grpOff = rvaToOff(dataRva);
  if (grpOff == null || size < 6) return;
  const ab = await file.slice(grpOff, grpOff + Math.min(size, 4096)).arrayBuffer();
  const g = new DataView(ab);
  const idCount = g.getUint16(4, true);
  if (!idCount || 6 + idCount * 14 > g.byteLength) return;
  let pick = 0;
  let bestW = 0;
  for (let index = 0; index < idCount; index++) {
    const w = g.getUint8(6 + index * 14 + 0) || 256;
    if (w === 32) {
      pick = index;
      bestW = w;
      break;
    }
    if (w > bestW) {
      pick = index;
      bestW = w;
    }
  }
  const eOff2 = 6 + pick * 14;
  const bWidth = g.getUint8(eOff2 + 0) || 256;
  const bHeight = g.getUint8(eOff2 + 1) || 256;
  const bColorCount = g.getUint8(eOff2 + 2);
  const wPlanes = g.getUint16(eOff2 + 4, true);
  const wBitCount = g.getUint16(eOff2 + 6, true);
  const nID = g.getUint16(eOff2 + 12, true);
  const ic = iconIndex.get(nID);
  if (!ic) return;
  const imgOff = rvaToOff(ic.rva);
  if (imgOff == null || ic.size <= 0 || ic.size > 2_000_000) return;
  const imageData = new Uint8Array(await file.slice(imgOff, imgOff + ic.size).arrayBuffer());
  const dirSize = 6 + 16;
  const ico = new Uint8Array(dirSize + imageData.length);
  const dv3 = new DataView(ico.buffer);
  dv3.setUint16(0, 0, true);
  dv3.setUint16(2, 1, true);
  dv3.setUint16(4, 1, true);
  dv3.setUint8(6, bWidth === 256 ? 0 : bWidth);
  dv3.setUint8(7, bHeight === 256 ? 0 : bHeight);
  dv3.setUint8(8, bColorCount);
  dv3.setUint8(9, 0);
  dv3.setUint16(10, wPlanes, true);
  dv3.setUint16(12, wBitCount, true);
  dv3.setUint32(14, imageData.length >>> 0, true);
  dv3.setUint32(18, dirSize >>> 0, true);
  ico.set(imageData, dirSize);
  langEntry.previewKind = "image";
  langEntry.previewMime = "image/x-icon";
  langEntry.previewDataUrl = `data:image/x-icon;base64,${base64FromU8(ico)}`;
}
