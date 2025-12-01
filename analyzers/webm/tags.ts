"use strict";

import {
  MAX_TAGS_BYTES,
  SIMPLE_TAG_ID,
  TAGS_ID,
  TAG_ID,
  TAG_BINARY_ID,
  TAG_DEFAULT_ID,
  TAG_LANGUAGE_ID,
  TAG_NAME_ID,
  TAG_STRING_ID,
  TAG_TARGET_TRACK_UID_ID,
  TARGETS_ID
} from "./constants.js";
import { clampReadLength, readElementHeader, readUnsigned, readUtf8 } from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues, WebmTagEntry } from "./types.js";

const parseSimpleTag = (
  dv: DataView,
  offset: number,
  size: number,
  issues: Issues,
  targetTrackUid: string | number | null
): WebmTagEntry => {
  const tag: WebmTagEntry = {
    name: null,
    value: null,
    binarySize: null,
    language: null,
    defaultFlag: null,
    targetTrackUid,
    truncated: false
  };
  let cursor = 0;
  const limit = Math.min(size, dv.byteLength - offset);
  while (cursor < limit) {
    const header = readElementHeader(dv, offset + cursor, offset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    const dataStart = offset + cursor + header.headerSize;
    const available = Math.min(header.size ?? 0, limit - (cursor + header.headerSize));
    if (header.id === TAG_NAME_ID && available > 0) {
      tag.name = readUtf8(dv, dataStart, available);
    } else if (header.id === TAG_STRING_ID && available > 0) {
      tag.value = readUtf8(dv, dataStart, available);
    } else if (header.id === TAG_BINARY_ID) {
      tag.binarySize = header.size;
    } else if (header.id === TAG_LANGUAGE_ID && available > 0) {
      tag.language = readUtf8(dv, dataStart, available);
    } else if (header.id === TAG_DEFAULT_ID && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "TagDefault");
      tag.defaultFlag = value != null ? Number(value) !== 0 : null;
    }
    if (header.size == null) break;
    cursor += header.headerSize + header.size;
  }
  if (cursor < size) tag.truncated = true;
  return tag;
};

export const parseTags = async (
  file: File,
  tagsHeader: EbmlElementHeader,
  issues: Issues
): Promise<WebmTagEntry[]> => {
  if (tagsHeader.id !== TAGS_ID) return [];
  const { length, truncated } = clampReadLength(file.size, tagsHeader.dataOffset, tagsHeader.size, MAX_TAGS_BYTES);
  const dv = new DataView(await file.slice(tagsHeader.dataOffset, tagsHeader.dataOffset + length).arrayBuffer());
  const limit = tagsHeader.size != null ? Math.min(tagsHeader.size, dv.byteLength) : dv.byteLength;
  const tags: WebmTagEntry[] = [];
  let cursor = 0;
  while (cursor < limit) {
    const tagHeader = readElementHeader(dv, cursor, tagsHeader.dataOffset + cursor, issues);
    if (!tagHeader || tagHeader.headerSize === 0 || tagHeader.size == null) break;
    if (tagHeader.id === TAG_ID) {
      const tagStart = cursor + tagHeader.headerSize;
      const tagLimit = Math.min(tagHeader.size, limit - tagStart);
      let targetTrackUid: string | number | null = null;
      let innerCursor = 0;
      while (innerCursor < tagLimit) {
        const innerHeader = readElementHeader(
          dv,
          tagStart + innerCursor,
          tagsHeader.dataOffset + tagStart + innerCursor,
          issues
        );
        if (!innerHeader || innerHeader.headerSize === 0 || innerHeader.size == null) break;
        const innerData = tagStart + innerCursor + innerHeader.headerSize;
        const innerAvailable = Math.min(innerHeader.size, tagStart + tagLimit - innerData);
        if (innerHeader.id === TARGETS_ID && innerAvailable > 0) {
          let targetCursor = 0;
          const targetEnd = innerAvailable;
          while (targetCursor < targetEnd) {
            const targetHeader = readElementHeader(
              dv,
              innerData + targetCursor,
              tagsHeader.dataOffset + innerData + targetCursor,
              issues
            );
            if (!targetHeader || targetHeader.headerSize === 0 || targetHeader.size == null) break;
            const targetData = innerData + targetCursor + targetHeader.headerSize;
            const targetAvailable = Math.min(targetHeader.size, innerData + targetEnd - targetData);
            if (targetHeader.id === TAG_TARGET_TRACK_UID_ID && targetAvailable > 0) {
              const uid = readUnsigned(dv, targetData, targetAvailable, issues, "TagTrackUID");
              if (uid != null) {
                targetTrackUid = uid > BigInt(Number.MAX_SAFE_INTEGER) ? uid.toString() : Number(uid);
              }
            }
            targetCursor += targetHeader.headerSize + targetHeader.size;
          }
        } else if (innerHeader.id === SIMPLE_TAG_ID) {
          const entry = parseSimpleTag(dv, innerData, innerHeader.size, issues, targetTrackUid);
          tags.push(entry);
        }
        innerCursor += innerHeader.headerSize + innerHeader.size;
      }
    }
    cursor += tagHeader.headerSize + tagHeader.size;
  }
  if (tagsHeader.size != null && truncated) issues.push("Tags section truncated.");
  return tags;
};
