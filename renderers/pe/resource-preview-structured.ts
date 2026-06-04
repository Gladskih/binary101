"use strict";

import type { ResourceLangWithPreview } from "../../analyzers/pe/resources/preview/types.js";
import { renderInfPreview } from "./resource-preview-inf.js";
import { renderTypeLibraryPreview } from "./resource-preview-type-library.js";
import { renderXmlPreview } from "./resource-preview-xml.js";

export const renderStructuredPreviewSummary = (
  langEntry: ResourceLangWithPreview
): string | null => {
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
  if (langEntry.previewKind === "inf" && langEntry.infPreview) {
    return renderInfPreview(langEntry.infPreview);
  }
  if (langEntry.previewKind === "xml") {
    return renderXmlPreview(langEntry.textPreview, langEntry.xmlTree);
  }
  if (langEntry.previewKind === "typeLibrary" && langEntry.typeLibrary) {
    return renderTypeLibraryPreview(langEntry.typeLibrary);
  }
  return null;
};
