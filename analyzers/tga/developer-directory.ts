"use strict";

import type { TgaDeveloperDirectory, TgaDeveloperTag } from "./types.js";
import { readUint16le, readUint32le } from "./tga-parsing.js";

const MAX_TAGS = 512;

export const parseTgaDeveloperDirectory = async (
  file: File,
  offset: number,
  pushIssue: (message: string) => void
): Promise<TgaDeveloperDirectory | null> => {
  if (offset <= 0 || offset >= file.size) return null;
  const headBytes = new Uint8Array(await file.slice(offset, Math.min(file.size, offset + 2)).arrayBuffer());
  const tagCount = readUint16le(headBytes, 0);
  if (tagCount == null) return { offset, tagCount: null, tags: [], truncated: true };

  const directoryBytes = 2 + tagCount * 10;
  const truncated = offset + directoryBytes > file.size;
  if (truncated) pushIssue("Developer directory truncated (file ends early).");

  const tags: TgaDeveloperTag[] = [];
  const parseLimit = Math.min(tagCount, MAX_TAGS);
  const bytesToRead = Math.min(file.size, offset + 2 + parseLimit * 10);
  const bytes = new Uint8Array(await file.slice(offset, bytesToRead).arrayBuffer());
  for (let index = 0; index < parseLimit; index += 1) {
    const entryOffset = 2 + index * 10;
    const tagNumber = readUint16le(bytes, entryOffset);
    const dataOffset = readUint32le(bytes, entryOffset + 2);
    const dataSize = readUint32le(bytes, entryOffset + 6);
    if (tagNumber == null || dataOffset == null || dataSize == null) break;
    tags.push({
      tagNumber,
      dataOffset,
      dataSize,
      truncated: dataOffset + dataSize > file.size
    });
  }
  if (tagCount > MAX_TAGS) pushIssue(`Developer directory has ${tagCount} tags; showing first ${MAX_TAGS}.`);
  return { offset, tagCount, tags, truncated };
};
