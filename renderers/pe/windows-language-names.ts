"use strict";

// Windows LANGID values are documented in "Language Identifier Constants and Strings".
// Source: https://learn.microsoft.com/en-us/windows/win32/intl/language-identifier-constants-and-strings
const exactLanguageNames = new Map<number, string>([
  [0x0000, "Neutral"],
  [0x007f, "Invariant"],
  [0x0404, "Chinese (Taiwan)"],
  [0x0407, "German (Germany)"],
  [0x0409, "English (United States)"],
  [0x040a, "Spanish (Traditional Sort)"],
  [0x040c, "French (France)"],
  [0x0410, "Italian (Italy)"],
  [0x0411, "Japanese (Japan)"],
  [0x0412, "Korean (Korea)"],
  [0x0415, "Polish (Poland)"],
  [0x0416, "Portuguese (Brazil)"],
  [0x0419, "Russian (Russia)"],
  [0x041d, "Swedish (Sweden)"],
  [0x0804, "Chinese (PRC)"],
  [0x0807, "German (Switzerland)"],
  [0x0809, "English (United Kingdom)"],
  [0x080a, "Spanish (Mexico)"],
  [0x080c, "French (Belgium)"],
  [0x0816, "Portuguese (Portugal)"],
  [0x0c0a, "Spanish (Spain)"]
]);

// The low 10 bits of LANGID carry the primary language identifier.
// Source: Microsoft Learn, Language Identifier Constants and Strings.
const primaryLanguageNames = new Map<number, string>([
  [0x00, "Neutral"],
  [0x04, "Chinese"],
  [0x07, "German"],
  [0x09, "English"],
  [0x0a, "Spanish"],
  [0x0c, "French"],
  [0x10, "Italian"],
  [0x11, "Japanese"],
  [0x12, "Korean"],
  [0x15, "Polish"],
  [0x16, "Portuguese"],
  [0x19, "Russian"],
  [0x1d, "Swedish"]
]);

const formatLangIdHex = (langId: number): string =>
  `0x${(langId >>> 0).toString(16).padStart(4, "0")}`;

export const formatWindowsLanguageName = (langId: number | null | undefined): string => {
  if (langId == null) return "-";
  const exact = exactLanguageNames.get(langId >>> 0);
  if (exact) return `${exact} (${formatLangIdHex(langId)})`;
  const primary = primaryLanguageNames.get((langId >>> 0) & 0x03ff);
  return primary ? `${primary} (${formatLangIdHex(langId)})` : formatLangIdHex(langId);
};
