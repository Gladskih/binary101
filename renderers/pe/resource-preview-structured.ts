"use strict";

import type { ResourcePreviewWithIssues } from "../../analyzers/pe/resources/preview/types.js";
import { renderInfPreview } from "./resource-preview-inf.js";
import { renderRegistryPreview } from "./resource-preview-registry.js";
import { escapeHtml } from "../../html-utils.js";
import { renderXmlPreview } from "./resource-preview-xml.js";
import { renderFontDirectoryPreview, renderLegacyFontPreview } from "./resource-preview-font.js";
import { renderDialogInitPreview, renderDialogLayoutPreview, renderToolbarPreview } from "./resource-preview-mfc.js";
import { renderWevtTemplatePreview } from "./resource-preview-wevt.js";
import { renderRibbonBmlPreview } from "./resource-preview-ribbon-bml.js";
import { renderRibbonXmlPreview } from "./resource-preview-ribbon-xml.js";
import { renderBinaryMofPreview } from "./resource-preview-mof.js";
import type { ResourcePreviewContext } from "./resource-preview-context.js";
import { renderDfmPreview } from "./resource-preview-dfm.js";
import { renderResourceAnimation } from "./resource-preview-animation.js";
import { renderVectorPreview } from "./resource-preview-vector.js";
import { renderEmbeddedDocument } from "./resource-preview-document.js";

const renderFontAndMfcSummary = (langEntry: ResourcePreviewWithIssues): string | null => {
  if (langEntry.fontDirectory) return `${langEntry.fontDirectory.entries.length} fonts`;
  if (langEntry.legacyFont) return `FNT ${langEntry.legacyFont.faceName || "font"}`;
  if (langEntry.dialogInit) return `${langEntry.dialogInit.entries.length} initialization records`;
  if (langEntry.dialogLayout) return `${langEntry.dialogLayout.controls.length} layout controls`;
  if (langEntry.toolbar) return `${langEntry.toolbar.items.length} toolbar items`;
  return null;
};

const renderAdditionalSummary = (langEntry: ResourcePreviewWithIssues): string | null => {
  if (langEntry.dfm) return `${langEntry.dfm.className} ${langEntry.dfm.name}`;
  if (langEntry.vector) return `${langEntry.vector.format} drawing`;
  if (langEntry.imageGroup) return `${langEntry.imageGroup.entries.length} ${langEntry.imageGroup.type} variants`;
  if (langEntry.embeddedDocument) return `Embedded ${langEntry.embeddedDocument.format}`;
  if (langEntry.ribbonBml) return `${langEntry.ribbonBml.commands.length} Ribbon commands`;
  if (langEntry.binaryMof) return `${langEntry.binaryMof.classes.length} WMI classes`;
  return null;
};

const typedSummary = (langEntry: ResourcePreviewWithIssues): string | null => {
  if (langEntry.previewKind === "inf" && langEntry.infPreview) {
    return `${langEntry.infPreview.sections.length} INF sections`;
  }
  if ((langEntry.previewKind === "xml" || langEntry.previewKind === "ribbonXml") &&
    langEntry.xmlTree) {
    return `XML <${langEntry.xmlTree.name}>`;
  }
  if (langEntry.previewKind === "typeLibrary" && langEntry.typeLibrary) {
    return `${langEntry.typeLibrary.format} type library`;
  }
  return null;
};

export const renderStructuredPreviewSummary = (
  langEntry: ResourcePreviewWithIssues
): string | null => {
  const media = renderAdditionalSummary(langEntry);
  if (media) return media;
  const additional = renderFontAndMfcSummary(langEntry);
  if (additional) return additional;
  if (langEntry.registry) return "ATL registry script";
  const typed = typedSummary(langEntry);
  if (typed) return typed;
  if (langEntry.wevtTemplate) {
    return `${langEntry.wevtTemplate.providers.length} event providers`;
  }
  return null;
};

const renderFontAndMfcPreview = (
  langEntry: ResourcePreviewWithIssues, context?: ResourcePreviewContext
): string | null => {
  if (langEntry.dfm) return renderDfmPreview(langEntry.dfm);
  if (langEntry.fontDirectory) return renderFontDirectoryPreview(langEntry.fontDirectory);
  if (langEntry.legacyFont) return renderLegacyFontPreview(langEntry.legacyFont);
  if (langEntry.dialogInit) return renderDialogInitPreview(langEntry.dialogInit);
  if (langEntry.dialogLayout) return renderDialogLayoutPreview(langEntry.dialogLayout);
  if (langEntry.toolbar) return renderToolbarPreview(langEntry.toolbar, context);
  return null;
};

const renderAdditionalPreview = (langEntry: ResourcePreviewWithIssues,
  context?: ResourcePreviewContext): string | null => {
  if (langEntry.animation) return renderResourceAnimation(langEntry.animation);
  if (langEntry.vector) return renderVectorPreview(langEntry.vector);
  if (langEntry.embeddedDocument) return renderEmbeddedDocument(langEntry.embeddedDocument, context);
  if (langEntry.ribbonBml) return renderRibbonBmlPreview(langEntry.ribbonBml, context);
  if (langEntry.binaryMof) return renderBinaryMofPreview(langEntry.binaryMof);
  const additional = renderFontAndMfcPreview(langEntry, context);
  if (additional) return additional;
  return null;
};

const typedPreview = (langEntry: ResourcePreviewWithIssues,
  context?: ResourcePreviewContext): string | null => {
  if (langEntry.previewKind === "inf" && langEntry.infPreview) {
    return renderInfPreview(langEntry.infPreview);
  }
  if (langEntry.previewKind === "ribbonXml") {
    return renderRibbonXmlPreview(langEntry.textPreview, langEntry.xmlTree, context);
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

export const renderStructuredPreview = (
  langEntry: ResourcePreviewWithIssues, registryTableId?: string, context?: ResourcePreviewContext
): string | null => {
  const additional = renderAdditionalPreview(langEntry, context);
  if (additional) return additional;
  if (langEntry.registry) return renderRegistryPreview(langEntry, registryTableId);
  const typed = typedPreview(langEntry, context);
  if (typed) return typed;
  if (langEntry.wevtTemplate) return renderWevtTemplatePreview(langEntry.wevtTemplate);
  return null;
};
