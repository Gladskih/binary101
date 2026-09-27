"use strict";

import type { ResourceLangWithPreview } from "../../analyzers/pe/resources/preview/types.js";
import { renderInfPreview } from "./resource-preview-inf.js";
import { escapeHtml } from "../../html-utils.js";
import { renderXmlPreview } from "./resource-preview-xml.js";
import { renderFontDirectoryPreview, renderLegacyFontPreview } from "./resource-preview-font.js";

export const renderStructuredPreviewSummary = (
  langEntry: ResourceLangWithPreview
): string | null => {
  if (langEntry.fontDirectory) return `${langEntry.fontDirectory.entries.length} fonts`;
  if (langEntry.legacyFont) return `FNT ${langEntry.legacyFont.faceName || "font"}`;
  if (langEntry.previewKind === "inf" && langEntry.infPreview) {
    return `${langEntry.infPreview.sections.length} INF sections`;
  }
  if (langEntry.previewKind === "xml" && langEntry.xmlTree) {
    return `XML <${langEntry.xmlTree.name}>`;
  }
  if (langEntry.previewKind === "typeLibrary" && langEntry.typeLibrary) {
    return `${langEntry.typeLibrary.format} type library`;
  }
  return null;
};

export const renderStructuredPreview = (
  langEntry: ResourceLangWithPreview
): string | null => {
  if (langEntry.fontDirectory) return renderFontDirectoryPreview(langEntry.fontDirectory);
  if (langEntry.legacyFont) return renderLegacyFontPreview(langEntry.legacyFont);
  if (langEntry.previewKind === "inf" && langEntry.infPreview) {
    return renderInfPreview(langEntry.infPreview);
  }
  if (langEntry.previewKind === "xml") {
    return renderXmlPreview(langEntry.textPreview, langEntry.xmlTree);
  }
  if (langEntry.previewKind === "typeLibrary" && langEntry.typeLibrary) {
    return `<p>${escapeHtml(langEntry.typeLibrary.format)} type library` +
      `${langEntry.typeLibrary.analysis?.name
        ? `: ${escapeHtml(langEntry.typeLibrary.analysis.name)}` : ""}. ` +
      `<a href="#pe-type-libraries">Detailed analysis in Type libraries (COM).</a></p>`;
  }
  return null;
};
