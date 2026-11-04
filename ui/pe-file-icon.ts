"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import type { ResourceCatalog } from "../analyzers/pe/resources/resource-index.js";
import type { ResourceLangWithPreview } from "../analyzers/pe/resources/preview/types.js";
import { indexResourceLeaves, resourceAt } from "../analyzers/pe/resources/resource-index.js";
import { resolveImageGroupTarget } from "../analyzers/pe/resources/preview/image-group-links.js";

// ICO directory dimensions use 0 to represent 256px. Source:
// https://learn.microsoft.com/en-us/windows/win32/menurc/iconresdir
const MAX_ICON_SCAN_DIMENSION = 256;

const clearPeFileIcon = (imageElement: HTMLImageElement, wrapperElement: HTMLElement): void => {
  wrapperElement.hidden = true;
  imageElement.alt = "";
  imageElement.removeAttribute("src");
};

const groupImageUrl = (catalog: ResourceCatalog, language: ResourceLangWithPreview): string | null => {
      const target = resolveImageGroupTarget(catalog, language);
      if (target) return resourceAt(catalog, target)?.previewDataUrl ?? null;
      if (language.previewKind === "image" && language.previewDataUrl?.startsWith("data:image/")) {
        return language.previewDataUrl;
      }
  return null;
};

const findPeFileIconDataUrl = (result: ParseForUiResult): string | null => {
  if (result.analyzer !== "pe" || !("resources" in result.parsed)) return null;
  const resources = result.parsed.resources;
  if (!resources) return null;
  const iconGroup = resources.detail.find(group => group.typeName === "GROUP_ICON");
  if (!iconGroup) return null;
  const catalog = indexResourceLeaves(resources.detail);
  for (const entry of iconGroup.entries) {
    for (const language of entry.langs) {
      const url = groupImageUrl(catalog, language);
      if (url) return url;
    }
  }
  return null;
};

export const renderPeFileIcon = (
  result: ParseForUiResult | null,
  fileName: string,
  imageElement: HTMLImageElement,
  wrapperElement: HTMLElement
): void => {
  const dataUrl = result ? findPeFileIconDataUrl(result) : null;
  wrapperElement.hidden = dataUrl == null;
  imageElement.alt = dataUrl ? `Icon embedded in ${fileName || "PE file"}` : "";
  if (dataUrl) imageElement.src = dataUrl;
  else clearPeFileIcon(imageElement, wrapperElement);
};

const hasVisibleIconPixels = (imageElement: HTMLImageElement): boolean => {
  const canvas = imageElement.ownerDocument.createElement("canvas");
  canvas.width = Math.min(MAX_ICON_SCAN_DIMENSION, imageElement.naturalWidth);
  canvas.height = Math.min(MAX_ICON_SCAN_DIMENSION, imageElement.naturalHeight);
  const context = canvas.getContext("2d");
  if (!context) return true;
  context.drawImage(imageElement, 0, 0, canvas.width, canvas.height);
  const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
  for (let index = 3; index < pixels.length; index += 4) {
    if (pixels[index] !== 0) return true;
  }
  return false;
};

const hideTransparentPeFileIcon = (imageElement: HTMLImageElement, wrapperElement: HTMLElement): void => {
  if (!imageElement.src || !imageElement.naturalWidth || !imageElement.naturalHeight) return;
  try {
    if (!hasVisibleIconPixels(imageElement)) clearPeFileIcon(imageElement, wrapperElement);
  } catch {
    clearPeFileIcon(imageElement, wrapperElement);
  }
};

export const attachPeFileIconGuard = (
  imageElement: HTMLImageElement,
  wrapperElement: HTMLElement
): void => {
  imageElement.addEventListener("error", () => clearPeFileIcon(imageElement, wrapperElement));
  imageElement.addEventListener("load", () => hideTransparentPeFileIcon(imageElement, wrapperElement));
};
