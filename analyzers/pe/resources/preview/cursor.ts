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
  if (typeName !== "GROUP_CURSOR" || data.length < 6) return null;
  const group = new DataView(data.buffer, data.byteOffset, data.byteLength);
  // RT_GROUP_CURSOR starts with NEWHEADER (6 bytes), then fixed-size 14-byte entries.
  const entryCount = group.getUint16(4, true);
  if (!entryCount || 6 + entryCount * 14 > data.length) return null;
  let selectedIndex = 0;
  let bestWidth = 0;
  for (let index = 0; index < entryCount; index += 1) {
    // UI heuristic: prefer a 32px cursor preview when present; otherwise pick the largest width.
    const width = group.getUint8(6 + index * 14) || 256;
    if (width === 32) {
      selectedIndex = index;
      break;
    }
    if (width > bestWidth) {
      selectedIndex = index;
      bestWidth = width;
    }
  }
  const entryOffset = 6 + selectedIndex * 14;
  const cursorId = group.getUint16(entryOffset + 12, true);
  const leaf = await loadLeafData(cursorId, lang);
  if (!leaf.data?.length || leaf.data.length <= CURSOR_LOCAL_HEADER_SIZE) {
    return leaf.issues?.length ? { issues: leaf.issues } : null;
  }
  const hotspotX = group.getUint16(entryOffset + 4, true);
  const hotspotY = group.getUint16(entryOffset + 6, true);
  const preview = buildCursorPreview(
    leaf.data.subarray(CURSOR_LOCAL_HEADER_SIZE),
    hotspotX,
    hotspotY
  );
  if (!leaf.issues?.length) return preview;
  return {
    ...preview,
    issues: [...(preview.issues || []), ...leaf.issues]
  };
}
