"use strict";

// US-ASCII graphic characters are 0x20..0x7e; CR/LF/TAB are accepted separately.
const PRINTABLE_ASCII_MIN = 0x20;
const PRINTABLE_ASCII_MAX = 0x7e;
const ASCII_DELETE = 0x7f;
const C1_CONTROL_MIN = 0x80;
const C1_CONTROL_MAX = 0x9f;

// Unicode block ranges: https://www.unicode.org/charts/
const SINHALA_MIN = 0x0d80;
const SINHALA_MAX = 0x0dff;
const TIBETAN_MIN = 0x0f00;
const TIBETAN_MAX = 0x0fff;
const GREEK_MIN = 0x0370;
const GREEK_MAX = 0x03ff;
const CYRILLIC_MIN = 0x0400;
const CYRILLIC_MAX = 0x04ff;
const ETHIOPIC_MIN = 0x1200;
const ETHIOPIC_MAX = 0x137f;
const HIRAGANA_MIN = 0x3040;
const HIRAGANA_MAX = 0x309f;
const KATAKANA_MIN = 0x30a0;
const KATAKANA_MAX = 0x30ff;
const CJK_EXTENSION_A_MIN = 0x3400;
const CJK_EXTENSION_A_MAX = 0x4dbf;
const CJK_UNIFIED_MIN = 0x4e00;
const CJK_UNIFIED_MAX = 0x9fff;
const HANGUL_SYLLABLES_MIN = 0xac00;
const HANGUL_SYLLABLES_MAX = 0xd7af;
const MISC_SYMBOLS_ARROWS_MIN = 0x2b00;
const MISC_SYMBOLS_ARROWS_MAX = 0x2bff;
const PRIVATE_USE_MIN = 0xe000;
const PRIVATE_USE_MAX = 0xf8ff;
const CJK_COMPATIBILITY_MIN = 0xf900;
const CJK_COMPATIBILITY_MAX = 0xfaff;
const ARABIC_PRESENTATION_FORMS_A_MIN = 0xfb50;
const ARABIC_PRESENTATION_FORMS_A_MAX = 0xfdff;
const ARABIC_PRESENTATION_FORMS_B_MIN = 0xfe70;
const ARABIC_PRESENTATION_FORMS_B_MAX = 0xfeff;
const JAVANESE_MIN = 0xa980;
const JAVANESE_MAX = 0xa9df;
const CHAM_MIN = 0xaa00;
const CHAM_MAX = 0xaa5f;
const TAI_VIET_MIN = 0xaa80;
const TAI_VIET_MAX = 0xaadf;
const MEETEI_MAYEK_EXTENSIONS_MIN = 0xaae0;
const MEETEI_MAYEK_EXTENSIONS_MAX = 0xaaff;
const ETHIOPIC_EXTENDED_A_MIN = 0xab00;
const ETHIOPIC_EXTENDED_A_MAX = 0xab2f;
const LATIN_EXTENDED_E_MIN = 0xab30;
const LATIN_EXTENDED_E_MAX = 0xab6f;
const CHEROKEE_SUPPLEMENT_MIN = 0xab70;
const CHEROKEE_SUPPLEMENT_MAX = 0xabbf;
const MEETEI_MAYEK_MIN = 0xabc0;
const MEETEI_MAYEK_MAX = 0xabff;

const inRange = (codePoint: number, min: number, max: number): boolean =>
  codePoint >= min && codePoint <= max;

const isPrintableAscii = (byte: number): boolean =>
  byte >= PRINTABLE_ASCII_MIN && byte <= PRINTABLE_ASCII_MAX;

const isTextControl = (codePoint: number): boolean =>
  codePoint === 0x09 || codePoint === 0x0a || codePoint === 0x0d;

export const isReasonableAsciiByte = (byte: number): boolean =>
  isPrintableAscii(byte) || isTextControl(byte);

export const hasOnlyReasonableText = (text: string): boolean => {
  for (const char of text) {
    const codePoint = char.codePointAt(0) ?? 0;
    if (codePoint < PRINTABLE_ASCII_MIN && !isTextControl(codePoint)) return false;
    if (codePoint === ASCII_DELETE) return false;
    if (inRange(codePoint, C1_CONTROL_MIN, C1_CONTROL_MAX)) return false;
    if (codePoint === 0xfffd) return false;
  }
  return text.length > 0;
};

const isAsciiTextCodePoint = (codePoint: number): boolean =>
  codePoint <= PRINTABLE_ASCII_MAX && isReasonableAsciiByte(codePoint);

const isCjkUnified = (codePoint: number): boolean =>
  inRange(codePoint, CJK_UNIFIED_MIN, CJK_UNIFIED_MAX);

const isHanLike = (codePoint: number): boolean =>
  isCjkUnified(codePoint) || inRange(codePoint, CJK_EXTENSION_A_MIN, CJK_EXTENSION_A_MAX);

const isPackedAsciiPair = (codePoint: number): boolean =>
  codePoint <= 0xffff &&
  isReasonableAsciiByte(codePoint & 0xff) &&
  isReasonableAsciiByte(codePoint >> 8);

const hasPackedAsciiPairs = (text: string): boolean => {
  let total = 0;
  let packed = 0;
  let packedSpaces = 0;
  for (const char of text) {
    const codePoint = char.codePointAt(0) ?? 0;
    total += 1;
    if (isPackedAsciiPair(codePoint)) {
      packed += 1;
      if ((codePoint & 0xff) === 0x20 || (codePoint >> 8) === 0x20) packedSpaces += 1;
    }
  }
  return total >= 6 && packedSpaces > 0 && packed * 2 >= total;
};

const asciiDominates = (counts: Map<number, number>, total: number): boolean => {
  for (const count of counts.values()) {
    if (count * 3 >= total * 2) return true;
  }
  return false;
};

const hasAlternatingAsciiHan = (text: string): boolean => {
  const asciiCounts = new Map<number, number>();
  let total = 0;
  let ascii = 0;
  let han = 0;
  let other = 0;
  let alternating = 0;
  let previousKind: "ascii" | "han" | "other" | null = null;
  for (const char of text) {
    const codePoint = char.codePointAt(0) ?? 0;
    const kind = isAsciiTextCodePoint(codePoint) ? "ascii" : isHanLike(codePoint) ? "han" : "other";
    total += 1;
    if (kind === "ascii") ascii += 1;
    if (kind === "han") han += 1;
    if (kind === "other") other += 1;
    if (kind === "ascii") asciiCounts.set(codePoint, (asciiCounts.get(codePoint) ?? 0) + 1);
    if (previousKind && kind !== "other" && previousKind !== "other" && kind !== previousKind) {
      alternating += 1;
    }
    previousKind = kind;
  }
  return total >= 5 &&
    ascii >= 2 &&
    han >= 2 &&
    other <= 2 &&
    alternating * 2 >= total - 1 &&
    asciiDominates(asciiCounts, ascii);
};

const isEastAsianText = (codePoint: number): boolean =>
  isHanLike(codePoint) ||
  inRange(codePoint, HIRAGANA_MIN, HIRAGANA_MAX) ||
  inRange(codePoint, KATAKANA_MIN, KATAKANA_MAX) ||
  inRange(codePoint, HANGUL_SYLLABLES_MIN, HANGUL_SYLLABLES_MAX);

const isPresentationForm = (codePoint: number): boolean =>
  inRange(codePoint, ARABIC_PRESENTATION_FORMS_A_MIN, ARABIC_PRESENTATION_FORMS_A_MAX) ||
  inRange(codePoint, ARABIC_PRESENTATION_FORMS_B_MIN, ARABIC_PRESENTATION_FORMS_B_MAX) ||
  inRange(codePoint, CJK_COMPATIBILITY_MIN, CJK_COMPATIBILITY_MAX);

const isRareIndicOrSoutheastAsian = (codePoint: number): boolean =>
  inRange(codePoint, JAVANESE_MIN, JAVANESE_MAX) ||
  inRange(codePoint, CHAM_MIN, CHAM_MAX) ||
  inRange(codePoint, TAI_VIET_MIN, TAI_VIET_MAX) ||
  inRange(codePoint, MEETEI_MAYEK_EXTENSIONS_MIN, MEETEI_MAYEK_EXTENSIONS_MAX) ||
  inRange(codePoint, ETHIOPIC_EXTENDED_A_MIN, ETHIOPIC_EXTENDED_A_MAX) ||
  inRange(codePoint, LATIN_EXTENDED_E_MIN, LATIN_EXTENDED_E_MAX) ||
  inRange(codePoint, CHEROKEE_SUPPLEMENT_MIN, CHEROKEE_SUPPLEMENT_MAX) ||
  inRange(codePoint, MEETEI_MAYEK_MIN, MEETEI_MAYEK_MAX);

const scriptBucket = (codePoint: number): string => {
  if (isEastAsianText(codePoint)) return "east-asian";
  if (inRange(codePoint, CYRILLIC_MIN, CYRILLIC_MAX)) return "cyrillic";
  if (inRange(codePoint, GREEK_MIN, GREEK_MAX)) return "greek";
  if (isPresentationForm(codePoint)) return "presentation";
  if (inRange(codePoint, TIBETAN_MIN, TIBETAN_MAX)) return "tibetan";
  if (inRange(codePoint, ETHIOPIC_MIN, ETHIOPIC_MAX)) return "ethiopic";
  if (inRange(codePoint, SINHALA_MIN, SINHALA_MAX)) return "sinhala";
  if (isRareIndicOrSoutheastAsian(codePoint)) return "rare-indic";
  if (inRange(codePoint, MISC_SYMBOLS_ARROWS_MIN, MISC_SYMBOLS_ARROWS_MAX)) return "symbols";
  return "other";
};

const isRareScript = (codePoint: number): boolean =>
  isPresentationForm(codePoint) ||
  inRange(codePoint, TIBETAN_MIN, TIBETAN_MAX) ||
  inRange(codePoint, ETHIOPIC_MIN, ETHIOPIC_MAX) ||
  inRange(codePoint, SINHALA_MIN, SINHALA_MAX) ||
  isRareIndicOrSoutheastAsian(codePoint);

const hasSequentialCodepointTable = (text: string): boolean => {
  let total = 0;
  let nonAscii = 0;
  let smallForwardSteps = 0;
  let previousCodePoint: number | null = null;
  for (const char of text) {
    const codePoint = char.codePointAt(0) ?? 0;
    total += 1;
    if (!isAsciiTextCodePoint(codePoint)) nonAscii += 1;
    if (previousCodePoint != null && codePoint > previousCodePoint) {
      if (codePoint - previousCodePoint <= 0x20) smallForwardSteps += 1;
    }
    previousCodePoint = codePoint;
  }
  return total >= 32 &&
    nonAscii * 4 >= total * 3 &&
    smallForwardSteps * 4 >= (total - 1) * 3;
};

const hasDisjointScriptSoup = (text: string): boolean => {
  const buckets = new Set<string>();
  let total = 0;
  let rare = 0;
  for (const char of text) {
    const codePoint = char.codePointAt(0) ?? 0;
    if (isAsciiTextCodePoint(codePoint)) continue;
    total += 1;
    if (inRange(codePoint, PRIVATE_USE_MIN, PRIVATE_USE_MAX)) return true;
    buckets.add(scriptBucket(codePoint));
    if (isRareScript(codePoint)) rare += 1;
  }
  return (total >= 4 && rare > 0 && buckets.size >= 3) ||
    (total >= 16 && buckets.size >= 3);
};

export const hasImplausibleWideTextShape = (text: string): boolean => {
  let total = 0;
  let cjkExtensionA = 0;
  let cjkUnified = 0;
  let hangul = 0;
  let symbols = 0;
  for (const char of text) {
    const codePoint = char.codePointAt(0) ?? 0;
    total += 1;
    if (inRange(codePoint, CJK_EXTENSION_A_MIN, CJK_EXTENSION_A_MAX)) cjkExtensionA += 1;
    if (inRange(codePoint, CJK_UNIFIED_MIN, CJK_UNIFIED_MAX)) cjkUnified += 1;
    if (inRange(codePoint, HANGUL_SYLLABLES_MIN, HANGUL_SYLLABLES_MAX)) hangul += 1;
    if (inRange(codePoint, MISC_SYMBOLS_ARROWS_MIN, MISC_SYMBOLS_ARROWS_MAX)) symbols += 1;
  }
  if (
    hasPackedAsciiPairs(text) ||
    hasAlternatingAsciiHan(text) ||
    hasSequentialCodepointTable(text) ||
    hasDisjointScriptSoup(text)
  ) {
    return true;
  }
  if (total < 8 || cjkExtensionA === 0) return false;
  if (cjkExtensionA * 4 >= total) return true;
  return cjkUnified > 0 && hangul > 0 && symbols > 0;
};
