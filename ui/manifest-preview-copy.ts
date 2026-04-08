"use strict";

import { copyHashToClipboard } from "./hash-controls.js";

type ElementLike = {
  closest(selector: string): ElementLike | null;
  querySelector?(selector: string): ElementLike | null;
};

type CopyStatus = "copied" | "failed" | "ignored";

export const copyManifestPreviewToClipboard = async (
  targetElement: Element | null
): Promise<CopyStatus> => {
  const button = (targetElement as ElementLike | null)?.closest("[data-manifest-copy-button]");
  if (!button) return "ignored";
  const preview = button.closest("[data-manifest-preview]");
  const source = preview?.querySelector?.("[data-manifest-copy-source]");
  if (!source) return "failed";
  return copyHashToClipboard(source as HTMLElement);
};
