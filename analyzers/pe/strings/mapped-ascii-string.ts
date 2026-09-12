"use strict";

import { mappedRvaSpan } from "../rva-mapping.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";

export type MappedAsciiString = {
  text: string;
  terminated: boolean;
  mappingStopped: boolean;
};

const isStringRequest = (startRva: number, fileSize: number, maxBytes: number, chunkSize: number) =>
  [startRva, fileSize, maxBytes, chunkSize].every(Number.isSafeInteger) &&
  startRva >= 0 && startRva < PE_RVA_EXCLUSIVE_LIMIT && maxBytes > 0 && chunkSize > 0;

export const readMappedNullTerminatedAsciiString = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  startRva: number,
  maxBytes: number,
  chunkSize = 64
): Promise<MappedAsciiString | null> => {
  if (!isStringRequest(startRva, fileSize, maxBytes, chunkSize)) return null;
  let text = "";
  let consumed = 0;
  while (consumed < maxBytes) {
    // Bound spread arguments and memory even when a caller supplies a very large chunk size.
    const span = mappedRvaSpan(rvaToOff, startRva + consumed,
      Math.min(chunkSize, 4096, maxBytes - consumed), fileSize);
    if (!span) return consumed === 0 ? null : { text, terminated: false, mappingStopped: true };
    const chunkView = await reader.read(span.offset, span.size);
    const chunk = new Uint8Array(chunkView.buffer, chunkView.byteOffset, chunkView.byteLength);
    const zeroIndex = chunk.indexOf(0);
    if (zeroIndex !== -1) {
      text += String.fromCharCode(...chunk.slice(0, zeroIndex));
      return { text, terminated: true, mappingStopped: false };
    }
    text += String.fromCharCode(...chunk);
    if (chunk.byteLength < span.size) return { text, terminated: false, mappingStopped: false };
    consumed += chunk.byteLength;
  }
  return { text, terminated: false, mappingStopped: false };
};
