"use strict";

import { parseAni } from "../ani/index.js";
import type { ResourcePreviewResult } from "./resources-preview-types.js";

const addAniTypePreview = async (
  data: Uint8Array,
  typeName: "ANICURSOR" | "ANIICON"
): Promise<ResourcePreviewResult | null> => {
  const payload = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  const parsed = await parseAni(new File([payload], `${typeName.toLowerCase()}.ani`));
  if (!parsed) return null;
  const detectedLabel = typeName === "ANICURSOR" ? "Animated cursor (ANI)" : "Animated icon (ANI)";
  const fields = [
    { label: "Type", value: typeName },
    { label: "Detected", value: detectedLabel },
    { label: "Frames", value: String(parsed.header?.frameCount ?? parsed.frames) },
    { label: "Steps", value: String(parsed.header?.stepCount ?? parsed.sequence.length) }
  ];
  if (parsed.header?.defaultFps != null) {
    fields.push({ label: "Default FPS", value: String(parsed.header.defaultFps) });
  }
  if (parsed.header?.width && parsed.header?.height) {
    fields.push({ label: "Dimensions", value: `${parsed.header.width}x${parsed.header.height}` });
  }
  return {
    preview: {
      previewKind: "summary",
      previewFields: fields
    },
    ...(parsed.issues.length ? { issues: parsed.issues } : {})
  };
};

export const addAniCursorPreview = (
  data: Uint8Array,
  typeName: string
): Promise<ResourcePreviewResult | null> =>
  typeName === "ANICURSOR" ? addAniTypePreview(data, "ANICURSOR") : Promise.resolve(null);

export const addAniIconPreview = (
  data: Uint8Array,
  typeName: string
): Promise<ResourcePreviewResult | null> =>
  typeName === "ANIICON" ? addAniTypePreview(data, "ANIICON") : Promise.resolve(null);
