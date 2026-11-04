"use strict";

import type {
  ResourcePreviewData,
  ResourcePreviewResult
} from "./types.js";
import {
  hasPngSignature,
  readIconImageSpec,
  type LoadResourceLeafData,
  wrapAsIco
} from "./icon.js";
import { makeDataUrl } from "./data-url.js";
import { addImageGroupPreview } from "./image-group.js";

const CURSOR_LOCAL_HEADER_SIZE = 4; // LOCALHEADER is two WORD hotspot fields.

const buildCursorPreview = (
  payload: Uint8Array,
  hotspotX: number,
  hotspotY: number
): ResourcePreviewResult => {
  if (hasPngSignature(payload)) {
    return {
      preview: {
        previewKind: "image",
        previewMime: "image/png",
        previewDataUrl: makeDataUrl("image/png", payload),
        previewFields: [{ label: "Hotspot", value: `${hotspotX}, ${hotspotY}` }]
      }
    };
  }
  const spec = readIconImageSpec(payload, true);
  if (!spec) {
    return { issues: ["CURSOR image payload is not a supported PNG or DIB icon frame."] };
  }
  const preview: ResourcePreviewData = {
    previewKind: "image",
    previewMime: "image/x-icon",
    previewDataUrl: makeDataUrl(
      "image/x-icon",
      wrapAsIco(payload, spec.width, spec.height, 0, 1, spec.bitCount)
    ),
    previewFields: [{ label: "Hotspot", value: `${hotspotX}, ${hotspotY}` }]
  };
  return { preview };
};

export const addCursorPreview = (
  data: Uint8Array,
  typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "CURSOR" || data.length <= CURSOR_LOCAL_HEADER_SIZE) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const hotspotX = view.getUint16(0, true);
  const hotspotY = view.getUint16(2, true);
  return buildCursorPreview(data.subarray(CURSOR_LOCAL_HEADER_SIZE), hotspotX, hotspotY);
};

export async function addGroupCursorPreview(
  data: Uint8Array,
  typeName: string,
  loadLeafData: LoadResourceLeafData,
  lang: number | null | undefined
): Promise<ResourcePreviewResult | null> {
  if (typeName !== "GROUP_CURSOR") return null;
  const metadata = addImageGroupPreview(data, typeName)!;
  const entries = metadata.preview?.imageGroup?.entries;
  if (!entries?.length) return metadata;
  // UI policy: prefer a conventional 32px cursor, otherwise the widest saved variant.
  const selected = entries.find(entry => entry.width === 32) ?? entries.reduce((best, entry) =>
    entry.width > best.width ? entry : best);
  return loadGroupCursorImage(selected.id, lang, loadLeafData, metadata.issues ?? []);
}

const loadGroupCursorImage = async (id: number, lang: number | null | undefined,
  loadLeafData: LoadResourceLeafData, metadataIssues: string[]): Promise<ResourcePreviewResult | null> => {
  const leaf = await loadLeafData(id, lang);
  if (!leaf.data?.length || leaf.data.length <= CURSOR_LOCAL_HEADER_SIZE) {
    return leaf.issues?.length ? { issues: leaf.issues } : null;
  }
  // RESDIR holds Planes/BitCount. LOCALHEADER in RT_CURSOR holds the hotspot.
  // https://learn.microsoft.com/en-us/windows/win32/menurc/localheader
  const preview = addCursorPreview(leaf.data, "CURSOR")!;
  const issues = [...metadataIssues, ...(preview.issues ?? []), ...(leaf.issues ?? [])];
  return {
    ...preview,
    ...(issues.length ? { issues } : {})
  };
};
