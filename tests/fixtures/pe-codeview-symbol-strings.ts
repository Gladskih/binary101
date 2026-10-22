import { legacyU16 } from "./pe-legacy-codeview.js";
import { codeViewTextRecord } from "./pe-codeview-type-strings.js";

export const codeViewUtf16 = (text: string): number[] => [
  ...Array.from({ length: text.length }, (_, index) => legacyU16(text.charCodeAt(index))).flat(), 0, 0
];

export const codeViewAnnotations = (strings: readonly number[], count: number): number[] => {
  const bytes = codeViewTextRecord(0x1019, 12, strings);
  bytes.splice(10, 2, ...legacyU16(count));
  return bytes;
};
