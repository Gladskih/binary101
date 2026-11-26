import type { PdfIndirectRef } from "./types.js";

// ISO 32000-2, 7.2: PDF has its own whitespace and delimiter sets.
const trivia = /(?:[\0\t\n\f\r ]+|%[^\r\n]*)*/y;
const regular = /[^\0\t\n\f\r ()<>[\]{}/%]+/y;
const name = /\/[^\0\t\n\f\r ()<>[\]{}/%]*/y;
const hexString = /<[\da-fA-F\0\t\n\f\r ]*>/y;
const numeric = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/;
const integer = /\+?\d+(?=[\0\t\n\f\r %])/y;
const referenceEnd = /R(?![^\0\t\n\f\r ()<>[\]{}/%])/y;

export const skipTrivia = (text: string, position: number): number => {
  trivia.lastIndex = position;
  return (trivia.exec(text)?.[0].length ?? 0) + position;
};

export const unsigned = (text: string | undefined): number | null => {
  if (!text || !/^\+?\d+$/.test(text)) return null;
  const value = Number(text);
  return Number.isSafeInteger(value) ? value : null;
};

export const readName = (token: string | undefined): string | null =>
  token?.startsWith("/") ? token.slice(1).replace(/#([\da-fA-F]{2})/g,
    (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16))) : null;

export const readReference = (token: string | undefined): PdfIndirectRef | null => {
  if (!token) return null;
  const reference = referenceAt(token, 0);
  return reference?.end === token.length ? reference.ref : null;
};

const matchLength = (pattern: RegExp, text: string, position: number): number => {
  pattern.lastIndex = position;
  return pattern.exec(text)?.[0].length ?? 0;
};

const referenceAt = (text: string, start: number) => {
  integer.lastIndex = start;
  const objectNumber = unsigned(integer.exec(text)?.[0]);
  if (!objectNumber) return null;
  integer.lastIndex = skipTrivia(text, integer.lastIndex);
  const generation = unsigned(integer.exec(text)?.[0]);
  if (generation == null || generation > 65535) return null;
  const end = skipTrivia(text, integer.lastIndex);
  return matchLength(referenceEnd, text, end)
    ? { ref: { objectNumber, generation }, end: end + 1 } : null;
};

const literalEnd = (text: string, start: number): number => {
  let depth = 1;
  for (let i = start + 1; i < text.length; i += 1) {
    switch (text[i]) {
      case "\\": i += 1; break;
      case "(": depth += 1; break;
      case ")": depth -= 1; break;
      default: break;
    }
    if (depth === 0) return i + 1;
  }
  return -1;
};

const scalarEnd = (text: string, start: number): number => {
  const first = text[start];
  if (first === "(") return literalEnd(text, start);
  if (first === "<") return start + matchLength(hexString, text, start);
  if (first === "/") return start + matchLength(name, text, start);
  const length = matchLength(regular, text, start);
  const token = text.slice(start, start + length);
  if (numeric.test(token)) return referenceAt(text, start)?.end ?? start + length;
  return ["true", "false", "null"].includes(token) ? start + length : -1;
};

const valueEnd = (text: string, start: number, depth: number): number => {
  // Limit JS recursion for deeply nested, untrusted direct objects.
  if (depth >= 64) return -1;
  if (text.startsWith("<<", start)) return dictionaryFields(text, start, depth + 1);
  if (text[start] === "[") return arrayItems(text, start, depth + 1);
  return scalarEnd(text, start);
};

const arrayItems = (text: string, start: number, depth: number, items?: string[]): number => {
  let position = skipTrivia(text, start + 1);
  while (text[position] !== "]") {
    const end = valueEnd(text, position, depth);
    if (end <= position) return -1;
    items?.push(text.slice(position, end));
    position = skipTrivia(text, end);
  }
  return position + 1;
};

const dictionaryFields = (
  text: string, start: number, depth: number, fields?: Map<string, string>
): number => {
  let position = skipTrivia(text, start + 2);
  while (!text.startsWith(">>", position)) {
    const length = matchLength(name, text, position);
    if (!length) return -1;
    const key = readName(text.slice(position, position + length))!;
    const valueStart = skipTrivia(text, position + length);
    const end = valueEnd(text, valueStart, depth);
    if (end <= valueStart || fields?.has(key)) return -1;
    fields?.set(key, text.slice(valueStart, end));
    position = skipTrivia(text, end);
  }
  return position + 2;
};

export interface PdfDictionary {
  raw: string;
  end: number;
  fields: ReadonlyMap<string, string>;
}

export const readDictionary = (text: string, offset = 0): PdfDictionary | null => {
  const start = skipTrivia(text, offset);
  if (!text.startsWith("<<", start)) return null;
  const fields = new Map<string, string>();
  const end = dictionaryFields(text, start, 0, fields);
  return end < 0 ? null : { raw: text.slice(start, end), end, fields };
};

export const readArray = (token: string | undefined): string[] | null => {
  if (!token?.startsWith("[")) return null;
  const items: string[] = [];
  return arrayItems(token, 0, 0, items) === token.length ? items : null;
};

export const readIntegerArray = (token: string | undefined): number[] | null => {
  const items = readArray(token)?.map(unsigned);
  return items?.every(item => item != null) ? items : null;
};
