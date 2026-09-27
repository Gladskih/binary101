"use strict";

import type { ResourceDetailGroup, ResourceLangWithPreview } from "./types.js";

const validateDirectory = (
  lang: ResourceLangWithPreview, fonts: Map<number, ResourceLangWithPreview[]>
): string[] => (lang.fontDirectory?.entries || []).flatMap(entry => {
  const candidates = fonts.get(entry.ordinal);
  if (!candidates?.length) return [`FONTDIR references missing FONT #${entry.ordinal}.`];
  const font = candidates.find(candidate => candidate.lang === lang.lang)?.legacyFont;
  if (font && (font.fileSize !== entry.font.fileSize || font.faceName !== entry.font.faceName)) {
    return [`FONTDIR metadata differs from FONT #${entry.ordinal} in this language.`];
  }
  return [];
});

export const validateFontReferences = (detail: ResourceDetailGroup[]): ResourceDetailGroup[] => {
  const fonts = new Map<number, ResourceLangWithPreview[]>();
  for (const group of detail.filter(group => group.typeName === "FONT")) {
    for (const entry of group.entries) {
      if (entry.id != null) fonts.set(entry.id, entry.langs);
    }
  }
  return detail.map(group => group.typeName !== "FONTDIR" ? group : {
    ...group, entries: group.entries.map(entry => ({
      ...entry, langs: entry.langs.map(lang => {
        const issues = validateDirectory(lang, fonts);
        return issues.length ? { ...lang, previewIssues: [...(lang.previewIssues || []), ...issues] } : lang;
      })
    }))
  });
};
