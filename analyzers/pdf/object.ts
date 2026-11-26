import type { FileRangeReader } from "../file-range-reader.js";
import { readDictionary, skipTrivia, unsigned } from "./syntax.js";
import type { PdfDictionary } from "./syntax.js";
import type { PdfIndirectRef } from "./types.js";

// Budget for structural dictionary syntax, independent of any following stream payload.
export const DICTIONARY_WINDOW = 64 * 1024;

export const decodePdfBytes = (bytes: Uint8Array): string => {
  const chunks: string[] = [];
  // Convert byte-for-code-unit without the Windows-1252 substitutions of TextDecoder("latin1").
  // Spread only a small chunk to stay below engine argument limits.
  const chunkSize = 8192;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    chunks.push(String.fromCharCode(...bytes.subarray(offset, offset + chunkSize)));
  }
  return chunks.join("");
};

export const readPdfText = async (
  reader: FileRangeReader, offset: number, length: number
): Promise<string> => decodePdfBytes(await reader.readBytes(offset, length));

export interface PdfIndirectDictionary {
  ref: PdfIndirectRef;
  dictionary: PdfDictionary;
  nextOffset: number;
  following: string;
}

export const parseIndirectDictionary = (text: string, offset: number): PdfIndirectDictionary | null => {
  const header = /^(\d+)[\0\t\n\f\r ]+(\d+)[\0\t\n\f\r ]+obj\b/.exec(text);
  if (!header) return null;
  const objectNumber = unsigned(header[1]);
  const generation = unsigned(header[2]);
  if (!objectNumber || generation == null || generation > 65535) return null;
  const dictionary = readDictionary(text, header[0].length);
  if (!dictionary) return null;
  const next = skipTrivia(text, dictionary.end);
  return {
    ref: { objectNumber, generation },
    dictionary,
    nextOffset: offset + next,
    following: text.slice(next, next + 12)
  };
};

export const readIndirectDictionary = async (
  reader: FileRangeReader, offset: number
): Promise<PdfIndirectDictionary | null> =>
  parseIndirectDictionary(await readPdfText(reader, offset, DICTIONARY_WINDOW), offset);
