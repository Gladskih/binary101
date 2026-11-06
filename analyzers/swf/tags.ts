import type { FileRangeReader } from "../file-range-reader.js";
import type { SwfParseResult, SwfTag } from "./types.js";

interface TagBoundary {
  code: number;
  start: number;
  offset: number;
  length: number;
}

const storeAttributes = (flags: number, result: SwfParseResult): void => {
  result.fileAttributes = flags;
  // Adobe SWF v19, FileAttributes: DirectBlit, GPU, Metadata, AS3, UseNetwork.
  // https://open-flash.github.io/mirrors/swf-spec-19.pdf
  if (flags & ~0x79) result.issues.push("SWF FileAttributes has reserved bits set.");
  if (result.version < 9 && (flags & 8)) result.issues.push("SWF ActionScript3 flag requires SWF 9 or later.");
  if (result.version < 10 && (flags & 0x60)) {
    result.issues.push("SWF GPU/direct-blit flags require SWF 10 or later.");
  }
};

export const readFirstSwfAttributes = async (
  reader: FileRangeReader, offset: number, result: SwfParseResult
): Promise<void> => {
  const view = await reader.read(offset, Math.min(10, reader.size - offset));
  const packed = view.byteLength >= 2 ? view.getUint16(0, true) : 0;
  const headerSize = (packed & 63) === 63 ? 6 : 2;
  const length = headerSize === 6 && view.byteLength >= 6 ? view.getUint32(2, true) : packed & 63;
  if (packed >>> 6 === 69 && length === 4 && view.byteLength >= headerSize + 4) {
    storeAttributes(view.getUint32(headerSize, true), result);
  } else if (result.version >= 8) {
    throw new Error("SWF 8 and later require a four-byte FileAttributes as the first tag.");
  }
};

const readSpecialTag = async (
  reader: FileRangeReader, tag: TagBoundary, firstTagOffset: number, result: SwfParseResult
): Promise<void> => {
  if (tag.code === 69) {
    if (tag.length !== 4) throw new Error("SWF FileAttributes must contain four bytes.");
    if (tag.start !== firstTagOffset) throw new Error("SWF FileAttributes is duplicated or is not the first tag.");
    const view = await reader.read(tag.offset, 4);
    if (view.byteLength !== 4) throw new Error("SWF FileAttributes is truncated.");
    storeAttributes(view.getUint32(0, true), result);
  } else if (tag.code === 77) {
    if (!tag.length) throw new Error("SWF Metadata tag is empty.");
    const tail = await reader.read(tag.offset + tag.length - 1, 1);
    if (tail.byteLength !== 1 || tail.getUint8(0) !== 0) {
      throw new Error("SWF metadata is truncated or is not NUL-terminated.");
    }
  }
};

const checkAttributeTags = (result: SwfParseResult, counts: Map<number, SwfTag>): void => {
  if (result.version >= 8 && result.fileAttributes == null) {
    result.issues.push("SWF 8 and later require FileAttributes as the first tag.");
  }
  if (result.fileAttributes != null && !!(result.fileAttributes & 16) !== counts.has(77)) {
    result.issues.push("SWF HasMetadata flag and Metadata tag disagree.");
  }
};

const finishTags = (result: SwfParseResult, counts: Map<number, SwfTag>): void => {
  checkAttributeTags(result, counts);
  if ((counts.get(1)?.count ?? 0) !== result.movie?.frameCount) {
    result.issues.push("SWF ShowFrame count differs from the declared frame count.");
  }
  if ((counts.get(77)?.count ?? 0) > 1) result.issues.push("SWF Metadata tag is duplicated.");
};

const countTag = (counts: Map<number, SwfTag>, code: number, length: number): void => {
  if ((code === 0 || code === 1) && length !== 0) {
    throw new Error("SWF End and ShowFrame tags must have empty bodies.");
  }
  const previous = counts.get(code);
  if (previous) { previous.count++; previous.bodyBytes += length; }
  else counts.set(code, { code, count: 1, bodyBytes: length });
};

const needsPayloadRead = (view: DataView, code: number, bodyIndex: number, length: number): boolean => {
  if (code !== 77) return code === 0 || code === 69;
  if (!length) throw new Error("SWF Metadata tag is empty.");
  if (bodyIndex + length > view.byteLength) return true;
  if (view.getUint8(bodyIndex + length - 1) !== 0) throw new Error("SWF metadata is not NUL-terminated.");
  return false;
};

const scanWindow = (
  view: DataView, start: number, fileEnd: number, counts: Map<number, SwfTag>
): { next: number; special?: TagBoundary } => {
  let index = 0;
  while (index + 2 <= view.byteLength) {
    const packed = view.getUint16(index, true);
    const shortLength = packed & 63;
    const headerLength = shortLength === 63 ? 6 : 2;
    if (index + headerLength > view.byteLength) break;
    const length = shortLength === 63 ? view.getUint32(index + 2, true) : shortLength;
    const offset = start + index + headerLength;
    if (offset + length > fileEnd) throw new Error("SWF tag body extends beyond the declared file boundary.");
    const code = packed >>> 6;
    countTag(counts, code, length);
    index += headerLength + length;
    if (needsPayloadRead(view, code, index - length, length)) {
      return { next: offset + length, special: { code, start: offset - headerLength, offset, length } };
    }
  }
  return { next: start + index };
};

export const readSwfTags = async (
  reader: FileRangeReader, firstTagOffset: number, result: SwfParseResult
): Promise<void> => {
  const counts = new Map<number, SwfTag>();
  let cursor = firstTagOffset;
  try {
    while (cursor < reader.size) {
      const view = await reader.read(cursor, Math.min(64 * 1024, reader.size - cursor));
      const scanned = scanWindow(view, cursor, reader.size, counts);
      if (scanned.next <= cursor) throw new Error("SWF tag header is truncated.");
      cursor = scanned.next;
      if (scanned.special?.code === 0) {
        result.tagEnd = cursor;
        if (cursor !== reader.size) result.issues.push("SWF has bytes after the End tag.");
        finishTags(result, counts);
        return;
      }
      if (scanned.special) await readSpecialTag(reader, scanned.special, firstTagOffset, result);
    }
    result.issues.push("SWF End tag is missing.");
  } finally {
    // Ten bits encode a tag code: aggregate in constant space even for dense files.
    result.tags = [...counts.values()];
  }
};
