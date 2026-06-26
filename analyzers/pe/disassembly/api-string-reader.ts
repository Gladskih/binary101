"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import type { RvaToOffset } from "../types.js";
import type { PeApiStringEncoding } from "./types.js";
import {
  peApiStringAddressToRva,
  type PeApiStringDecoded,
  type PeApiStringPendingReference
} from "./api-string-reference-model.js";

// Per-candidate cap keeps malformed or unterminated strings from driving unbounded reads.
const MAX_STRING_BYTES = 4096;
// Chunked random reads avoid one range-reader call per character while staying bounded.
const READ_CHUNK_BYTES = 256;
// US-ASCII graphic characters are 0x20..0x7e; CR/LF/TAB are accepted separately.
const PRINTABLE_ASCII_MIN = 0x20;
const PRINTABLE_ASCII_MAX = 0x7e;

const isPrintableAscii = (byte: number): boolean =>
  byte >= PRINTABLE_ASCII_MIN && byte <= PRINTABLE_ASCII_MAX;

const isTextControl = (codePoint: number): boolean =>
  codePoint === 0x09 || codePoint === 0x0a || codePoint === 0x0d;

const isReasonableAsciiByte = (byte: number): boolean =>
  isPrintableAscii(byte) || isTextControl(byte);

const hasOnlyReasonableText = (text: string): boolean => {
  for (const char of text) {
    const codePoint = char.codePointAt(0) ?? 0;
    if (codePoint < PRINTABLE_ASCII_MIN && !isTextControl(codePoint)) return false;
    if (codePoint === 0xfffd) return false;
  }
  return text.length > 0;
};

const decodeNarrowString = (
  bytes: Uint8Array,
  requestedEncoding: PeApiStringEncoding
): { encoding: PeApiStringEncoding; text: string } | null => {
  if (bytes.every(isReasonableAsciiByte)) {
    return {
      encoding: requestedEncoding === "utf-8" ? "utf-8" : "ascii",
      text: String.fromCharCode(...bytes)
    };
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return hasOnlyReasonableText(text) ? { encoding: "utf-8", text } : null;
  } catch {
    return null;
  }
};

const decodeWideString = (bytes: Uint8Array): string | null => {
  if (bytes.byteLength % 2 !== 0) return null;
  try {
    const text = new TextDecoder("utf-16le", { fatal: true }).decode(bytes);
    return hasOnlyReasonableText(text) ? text : null;
  } catch {
    return null;
  }
};

const mappedContiguousChunkSize = (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  startRva: number,
  startOffset: number,
  consumed: number,
  unitSize: number
): number => {
  const rva = startRva + consumed;
  if (rva > PE_RVA_EXCLUSIVE_LIMIT - unitSize) return 0;
  const offset = rvaToOff(rva >>> 0);
  if (offset == null || offset < 0 || offset !== startOffset + consumed) return 0;
  if (offset >= reader.size) return 0;
  const maxSize = Math.min(READ_CHUNK_BYTES, MAX_STRING_BYTES - consumed, reader.size - offset);
  return Math.floor(maxSize / unitSize) * unitSize;
};

const findTerminatorOffset = (bytes: Uint8Array, unitSize: number): number | null => {
  const alignedLength = bytes.byteLength - (bytes.byteLength % unitSize);
  for (let offset = 0; offset < alignedLength; offset += unitSize) {
    let terminated = true;
    for (let index = 0; index < unitSize; index += 1) {
      if (bytes[offset + index] !== 0) terminated = false;
    }
    if (terminated) return offset;
  }
  return null;
};

const appendBytes = (
  out: number[],
  bytes: Uint8Array,
  byteLength: number
): void => {
  for (let index = 0; index < byteLength; index += 1) out.push(bytes[index] ?? 0);
};

const readMappedBytes = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  startRva: number,
  unitSize: number
): Promise<Uint8Array | null> => {
  const startOffset = rvaToOff(startRva);
  if (startOffset == null || startOffset < 0 || startOffset >= reader.size) return null;
  const bytes: number[] = [];
  for (let consumed = 0; consumed < MAX_STRING_BYTES;) {
    const size = mappedContiguousChunkSize(
      reader,
      rvaToOff,
      startRva,
      startOffset,
      consumed,
      unitSize
    );
    if (size <= 0) return null;
    const view = await reader.read(startOffset + consumed, size);
    if (view.byteLength < size) return null;
    const chunk = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    const terminatorOffset = findTerminatorOffset(chunk, unitSize);
    if (terminatorOffset != null) {
      appendBytes(bytes, chunk, terminatorOffset);
      return Uint8Array.from(bytes);
    }
    appendBytes(bytes, chunk, size);
    consumed += size;
  }
  return null;
};

export const readPeApiStringCandidate = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  candidate: PeApiStringPendingReference
): Promise<PeApiStringDecoded | null> => {
  const rva = peApiStringAddressToRva(candidate.address, imageBase);
  if (rva == null) return null;
  const unitSize = candidate.encoding === "utf-16le"
    ? Uint16Array.BYTES_PER_ELEMENT
    : Uint8Array.BYTES_PER_ELEMENT;
  const bytes = await readMappedBytes(reader, rvaToOff, rva, unitSize);
  if (!bytes || bytes.byteLength === 0) return null;
  if (candidate.encoding === "utf-16le") {
    const text = decodeWideString(bytes);
    return text ? { rva, encoding: "utf-16le", byteLength: bytes.byteLength, text } : null;
  }
  const decoded = decodeNarrowString(bytes, candidate.encoding);
  return decoded ? { rva, byteLength: bytes.byteLength, ...decoded } : null;
};

export const peApiStringReferenceKey = (decoded: PeApiStringDecoded): string =>
  `${decoded.rva}:${decoded.encoding}`;
