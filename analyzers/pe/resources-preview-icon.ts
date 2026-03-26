"use strict";

import { makeDataUrl } from "./resource-preview-data-url.js";
import { hasPngSignature } from "./resource-preview-signatures.js";
import type {
  ResourcePreviewData,
  ResourcePreviewResult
} from "./resources-preview-types.js";

export type LoadedResourceLeaf = {
  data: Uint8Array | null;
  issues?: string[];
};

export type LoadResourceLeafData = (
  id: number,
  lang: number | null | undefined
) => Promise<LoadedResourceLeaf>;

const readIconImageSpec = (
  data: Uint8Array,
  halveHeight: boolean
): { width: number; height: number; bitCount: number } | null => {
  if (data.length < 40) return null;
  const view = new DataView(data.buffer, data.byteOffset, Math.min(64, data.length));
  const headerSize = view.getUint32(0, true);
  // Icon/cursor DIB payloads commonly start with BITMAPINFOHEADER/BITMAPV4HEADER/BITMAPV5HEADER.
  if (headerSize !== 40 && headerSize !== 108 && headerSize !== 124) return null;
  const width = Math.max(1, Math.min(256, Math.abs(view.getInt32(4, true))));
  const storedHeight = Math.abs(view.getInt32(8, true));
  const height = Math.max(1, Math.min(256, halveHeight ? Math.floor(storedHeight / 2) : storedHeight));
  return { width, height, bitCount: view.getUint16(14, true) };
};

const wrapAsIco = (
  imageData: Uint8Array,
  width: number,
  height: number,
  colorCount: number,
  planes: number,
  bitCount: number
): Uint8Array => {
  // ICO = ICONDIR (6 bytes) + one ICONDIRENTRY (16 bytes) + image payload.
  const headerSize = 6 + 16;
  const ico = new Uint8Array(headerSize + imageData.length);
  const view = new DataView(ico.buffer);
  view.setUint16(0, 0, true);
  view.setUint16(2, 1, true);
  view.setUint16(4, 1, true);
  // ICONDIRENTRY encodes 256px as 0 for width/height. Source:
  // Microsoft Learn, ICONRESDIR / https://learn.microsoft.com/en-us/windows/win32/menurc/iconresdir
  view.setUint8(6, width === 256 ? 0 : width);
  view.setUint8(7, height === 256 ? 0 : height);
  view.setUint8(8, colorCount);
  view.setUint8(9, 0);
  view.setUint16(10, planes, true);
  view.setUint16(12, bitCount, true);
  view.setUint32(14, imageData.length >>> 0, true);
  view.setUint32(18, headerSize >>> 0, true);
  ico.set(imageData, headerSize);
  return ico;
};

const buildIcoPreview = (
  imageData: Uint8Array,
  width: number,
  height: number,
  colorCount: number,
  planes: number,
  bitCount: number
): ResourcePreviewData => ({
  previewKind: "image",
  previewMime: "image/x-icon",
  previewDataUrl: makeDataUrl(
    "image/x-icon",
    wrapAsIco(imageData, width, height, colorCount, planes, bitCount)
  )
});

export function addIconPreview(data: Uint8Array, typeName: string): ResourcePreviewResult | null {
  if (typeName !== "ICON") return null;
  if (hasPngSignature(data)) {
    return {
      preview: {
        previewKind: "image",
        previewMime: "image/png",
        previewDataUrl: makeDataUrl("image/png", data)
      }
    };
  }
  const spec = readIconImageSpec(data, true);
  if (!spec) return null;
  return { preview: buildIcoPreview(data, spec.width, spec.height, 0, 1, spec.bitCount) };
}

const pickBestGroupEntry = (groupData: DataView): number | null => {
  const entryCount = groupData.getUint16(4, true);
  // RT_GROUP_ICON starts with NEWHEADER (6 bytes), then fixed-size 14-byte RESDIR records.
  if (!entryCount || 6 + entryCount * 14 > groupData.byteLength) return null;
  let selectedIndex = 0;
  let bestWidth = 0;
  for (let index = 0; index < entryCount; index += 1) {
    // UI heuristic: prefer a 32px icon preview when present; otherwise pick the largest width.
    const width = groupData.getUint8(6 + index * 14) || 256;
    if (width === 32) return index;
    if (width > bestWidth) {
      selectedIndex = index;
      bestWidth = width;
    }
  }
  return selectedIndex;
};

export async function addGroupIconPreview(
  data: Uint8Array,
  typeName: string,
  loadLeafData: LoadResourceLeafData,
  lang: number | null | undefined
): Promise<ResourcePreviewResult | null> {
  if (typeName !== "GROUP_ICON" || data.length < 6) return null;
  const group = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const selectedIndex = pickBestGroupEntry(group);
  if (selectedIndex == null) return null;
  const entryOffset = 6 + selectedIndex * 14;
  const iconId = group.getUint16(entryOffset + 12, true);
  const leaf = await loadLeafData(iconId, lang);
  if (!leaf.data?.length) return leaf.issues?.length ? { issues: leaf.issues } : null;
  const width = group.getUint8(entryOffset) || 256;
  const height = group.getUint8(entryOffset + 1) || 256;
  const colorCount = group.getUint8(entryOffset + 2);
  const planes = group.getUint16(entryOffset + 4, true);
  const bitCount = group.getUint16(entryOffset + 6, true);
  return {
    preview: buildIcoPreview(leaf.data, width, height, colorCount, planes, bitCount),
    ...(leaf.issues?.length ? { issues: leaf.issues } : {})
  };
}

export { hasPngSignature, readIconImageSpec, wrapAsIco };
