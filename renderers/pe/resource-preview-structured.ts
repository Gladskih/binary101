"use strict";

import type { ResourceLangWithPreview } from "../../analyzers/pe/resources/preview/types.js";
import { renderInfPreview } from "./resource-preview-inf.js";
import { renderRegistryPreview } from "./resource-preview-registry.js";
import { escapeHtml } from "../../html-utils.js";
import { renderXmlPreview } from "./resource-preview-xml.js";
import { renderFontDirectoryPreview, renderLegacyFontPreview } from "./resource-preview-font.js";
import { renderDialogInitPreview, renderDialogLayoutPreview, renderToolbarPreview } from "./resource-preview-mfc.js";
import { renderWevtTemplatePreview } from "./resource-preview-wevt.js";

const renderFontAndMfcSummary = (langEntry: ResourceLangWithPreview): string | null => {
  if (langEntry.fontDirectory) return `${langEntry.fontDirectory.entries.length} fonts`;
  if (langEntry.legacyFont) return `FNT ${langEntry.legacyFont.faceName || "font"}`;
  if (langEntry.dialogInit) return `${langEntry.dialogInit.entries.length} initialization records`;
  if (langEntry.dialogLayout) return `${langEntry.dialogLayout.controls.length} layout controls`;
  if (langEntry.toolbar) return `${langEntry.toolbar.items.length} toolbar items`;
  return null;
};

export const renderStructuredPreviewSummary = (
  langEntry: ResourceLangWithPreview
): string | null => {
  const additional = renderFontAndMfcSummary(langEntry);
  if (additional) return additional;
  if (langEntry.registry) return "ATL registry script";
  if (langEntry.previewKind === "inf" && langEntry.infPreview) {
    return `${langEntry.infPreview.sections.length} INF sections`;
  }
  if (langEntry.previewKind === "xml" && langEntry.xmlTree) {
    return `XML <${langEntry.xmlTree.name}>`;
  }
  if (langEntry.previewKind === "typeLibrary" && langEntry.typeLibrary) {
    return `${langEntry.typeLibrary.format} type library`;
  }
  if (langEntry.wevtTemplate) {
    return `${langEntry.wevtTemplate.providers.length} event providers`;
  }
  return null;
};

const renderFontAndMfcPreview = (langEntry: ResourceLangWithPreview): string | null => {
  if (langEntry.fontDirectory) return renderFontDirectoryPreview(langEntry.fontDirectory);
  if (langEntry.legacyFont) return renderLegacyFontPreview(langEntry.legacyFont);
  if (langEntry.dialogInit) return renderDialogInitPreview(langEntry.dialogInit);
  if (langEntry.dialogLayout) return renderDialogLayoutPreview(langEntry.dialogLayout);
  if (langEntry.toolbar) return renderToolbarPreview(langEntry.toolbar);
  return null;
};

export const renderStructuredPreview = (
  langEntry: ResourceLangWithPreview, registryTableId?: string
): string | null => {
  const additional = renderFontAndMfcPreview(langEntry);
  if (additional) return additional;
  if (langEntry.registry) return renderRegistryPreview(langEntry, registryTableId);
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
  if (langEntry.wevtTemplate) return renderWevtTemplatePreview(langEntry.wevtTemplate);
  return null;
};
