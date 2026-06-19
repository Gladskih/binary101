"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";

const findPeFileIconDataUrl = (result: ParseForUiResult): string | null => {
  if (result.analyzer !== "pe" || !("resources" in result.parsed)) return null;
  const iconGroup = result.parsed.resources?.detail.find(group => group.typeName === "GROUP_ICON");
  for (const entry of iconGroup?.entries ?? []) {
    for (const language of entry.langs) {
      if (language.previewKind === "image" && language.previewDataUrl?.startsWith("data:image/")) {
        return language.previewDataUrl;
      }
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
  else imageElement.removeAttribute("src");
};
