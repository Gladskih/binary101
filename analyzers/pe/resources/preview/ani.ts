"use strict";

import { parseAniAnimation } from "./ani-animation.js";
import type { ResourcePreviewResult } from "./types.js";

const addAniTypePreview = async (
  data: Uint8Array,
  typeName: "ANICURSOR" | "ANIICON"
): Promise<ResourcePreviewResult | null> => {
  const issues: string[] = [];
  const parsed = parseAniAnimation(data, issues);
  if (!parsed) return null;
  const detectedLabel = typeName === "ANICURSOR" ? "Animated cursor (ANI)" : "Animated icon (ANI)";
  const fields = [
    { label: "Type", value: typeName },
    { label: "Detected", value: detectedLabel },
    { label: "Frames", value: String(parsed.declaredFrames) },
    { label: "Steps", value: String(parsed.declaredSteps) }
  ];
  return {
    preview: {
      previewKind: "summary",
      previewFields: fields,
      animation: parsed
    },
    ...(issues.length ? { issues } : {})
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
