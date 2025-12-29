"use strict";

import {
  INFO_ID,
  MAX_SEEK_BYTES,
  SEEK_ENTRY_ID,
  SEEK_HEAD_ID,
  SEEK_ID_ID,
  SEEK_POSITION_ID,
  SEGMENT_ID,
  TRACKS_ID
} from "./constants.js";
import { clampReadLength, readElementHeader, readUnsigned } from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues, WebmSeekHead } from "./types.js";

const describeElement = (id: number): string => {
  switch (id) {
    case SEGMENT_ID:
      return "Segment";
    case INFO_ID:
      return "Segment Info";
    case TRACKS_ID:
      return "Tracks";
    case SEEK_HEAD_ID:
      return "SeekHead";
    default:
      return `0x${id.toString(16)}`;
  }
};

export const parseSeekHead = async (
  file: File,
  seekHead: EbmlElementHeader,
  segmentDataStart: number,
  issues: Issues
): Promise<WebmSeekHead> => {
  const { length, truncated } = clampReadLength(file.size, seekHead.dataOffset, seekHead.size, MAX_SEEK_BYTES);
  const dv = new DataView(await file.slice(seekHead.dataOffset, seekHead.dataOffset + length).arrayBuffer());
  const limit = seekHead.size != null ? Math.min(seekHead.size, dv.byteLength) : dv.byteLength;
  const entries: WebmSeekHead["entries"] = [];
  let cursor = 0;
  while (cursor < limit) {
    const entryHeader = readElementHeader(dv, cursor, seekHead.dataOffset + cursor, issues);
    if (!entryHeader || entryHeader.headerSize === 0) break;
    const dataStart = cursor + entryHeader.headerSize;
    const available = Math.min(entryHeader.size ?? 0, limit - dataStart);
    if (entryHeader.id === SEEK_ENTRY_ID && available > 0) {
      let id = 0;
      let position: number | null = null;
      let absoluteOffset: number | null = null;
      let innerCursor = dataStart;
      const entryEnd = dataStart + available;
      while (innerCursor < entryEnd) {
        const innerHeader = readElementHeader(dv, innerCursor, seekHead.dataOffset + innerCursor, issues);
        if (!innerHeader || innerHeader.headerSize === 0 || innerHeader.size == null) break;
        const innerData = innerCursor + innerHeader.headerSize;
        const innerAvailable = Math.min(innerHeader.size, entryEnd - innerData);
        if (innerHeader.id === SEEK_ID_ID && innerAvailable > 0) {
          id = new Uint8Array(dv.buffer, dv.byteOffset + innerData, innerAvailable).reduce(
            (acc, byte) => (acc << 8) | byte,
            0
          );
        } else if (innerHeader.id === SEEK_POSITION_ID && innerAvailable > 0) {
          const posValue = readUnsigned(dv, innerData, innerAvailable, issues, "SeekPosition");
          if (posValue != null) {
            const asNumber = Number(posValue);
            if (Number.isSafeInteger(asNumber)) {
              position = asNumber;
              absoluteOffset = segmentDataStart + asNumber;
            } else {
              issues.push("SeekPosition exceeds safe integer range.");
            }
          }
        }
        innerCursor += innerHeader.headerSize + innerHeader.size;
      }
      entries.push({
        id,
        name: describeElement(id),
        position,
        absoluteOffset
      });
    }
    if (entryHeader.size == null) break;
    cursor += entryHeader.headerSize + entryHeader.size;
  }
  return { entries, truncated: truncated || (seekHead.size != null && length < seekHead.size) };
};

