"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { RvaToOffset } from "./types.js";

export type MappedAsciiString = {
  text: string;
  terminated: boolean;
  mappingStopped: boolean;
};

export const readMappedNullTerminatedAsciiString = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  startRva: number,
  maxBytes: number,
  chunkSize = 64
): Promise<MappedAsciiString | null> => {
  const startOffset = rvaToOff(startRva);
  if (startOffset == null || startOffset < 0 || startOffset >= fileSize || maxBytes <= 0) return null;
  let text = "";
  let consumed = 0;
  while (consumed < maxBytes && startOffset + consumed < fileSize) {
    const remaining = Math.min(chunkSize, maxBytes - consumed, fileSize - (startOffset + consumed));
    let contiguous = 0;
    while (contiguous < remaining) {
      const mappedOffset = rvaToOff((startRva + consumed + contiguous) >>> 0);
      const expectedOffset = startOffset + consumed + contiguous;
      if (mappedOffset == null || mappedOffset !== expectedOffset) break;
      contiguous += 1;
    }
    if (contiguous === 0) return { text, terminated: false, mappingStopped: true };
    const chunkView = await reader.read(startOffset + consumed, contiguous);
    const chunk = new Uint8Array(chunkView.buffer, chunkView.byteOffset, chunkView.byteLength);
    if (chunk.byteLength === 0) return { text, terminated: false, mappingStopped: false };
    const zeroIndex = chunk.indexOf(0);
    if (zeroIndex !== -1) {
      if (zeroIndex > 0) text += String.fromCharCode(...chunk.slice(0, zeroIndex));
      return { text, terminated: true, mappingStopped: false };
    }
    text += String.fromCharCode(...chunk);
    consumed += chunk.byteLength;
    if (contiguous < remaining) return { text, terminated: false, mappingStopped: true };
  }
  return { text, terminated: false, mappingStopped: false };
};
