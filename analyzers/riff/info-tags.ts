"use strict";

import { findListChunks } from "./chunk-query.js";
import type { RiffParseResult, RiffChunk } from "./types.js";

export interface RiffInfoTag {
  id: string;
  value: string;
  offset: number;
  truncated: boolean;
}

const decodeAscii = (dv: DataView, offset: number, length: number): string => {
  let text = "";
  for (let i = 0; i < length && offset + i < dv.byteLength; i += 1) {
    const byte = dv.getUint8(offset + i);
    if (byte === 0) break;
    if (byte >= 0x09 && byte <= 0x7e) text += String.fromCharCode(byte);
  }
  return text.trim();
};

const collectInfoTagsFromList = (
  dv: DataView,
  listChunk: RiffChunk,
  tags: RiffInfoTag[]
): void => {
  if (!listChunk.children || listChunk.children.length === 0) return;
  for (const child of listChunk.children) {
    if (!child.id) continue;
    const readable = Math.max(
      0,
      Math.min(child.size, dv.byteLength - child.dataOffset)
    );
    const value = decodeAscii(dv, child.dataOffset, readable);
    if (value) {
      tags.push({
        id: child.id,
        value,
        offset: child.offset,
        truncated: child.truncated || readable < child.size
      });
    }
  }
};

export const parseInfoTags = (
  dv: DataView,
  riff: RiffParseResult
): RiffInfoTag[] => {
  const tags: RiffInfoTag[] = [];
  const infoLists = findListChunks(riff.chunks, "INFO");
  for (const listChunk of infoLists) {
    collectInfoTagsFromList(dv, listChunk, tags);
  }
  return tags;
};
