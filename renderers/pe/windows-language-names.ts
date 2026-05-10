"use strict";

import languageTags from "./windows-language-tags.generated.json" with { type: "json" };

// Generated from Microsoft [MS-LCID] LCID Structure, Language ID table:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid/63d3d639-7fd2-4afb-abbe-0d5b5551eef8
const displayNames = new Intl.DisplayNames(["en"], { type: "language" });

const formatLangIdHex = (langId: number): string =>
  `0x${(langId >>> 0).toString(16).padStart(4, "0")}`;

const formatTag = (tag: string, hex: string): string => {
  const name = displayNames.of(tag);
  return name && name !== tag ? `${name} (${tag}, ${hex})` : `${tag} (${hex})`;
};

export const formatWindowsLanguageName = (langId: number | null | undefined): string => {
  if (langId == null) return "-";
  const hex = formatLangIdHex(langId);
  const tag = (languageTags as Record<string, string>)[hex];
  return tag ? formatTag(tag, hex) : hex;
};
