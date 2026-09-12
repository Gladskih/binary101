"use strict";

import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import { mappedRvaSize, mappedRvaSpan, isRvaRange } from "../rva-mapping.js";
import type { RvaToOffset } from "../types.js";
import type { PeDataDirectory } from "../types.js";

export interface ResourceSpanResolver {
  readRelative: (view: (offset: number, length: number) => Promise<DataView>,
    rel: number, length: number) => Promise<DataView>;
  formatRelOffset: (rel: number) => string;
  describeRelOffsetFailure: (rel: number, len: number, subject: string) => string;
  resolveRvaOffset: (rva: number) => number | null;
  resolveRelOffset: (rel: number, len: number) => number | null;
}

export const formatResourceRelOffset = (rel: number): string => `0x${(rel >>> 0).toString(16)}`;

const isResourceRelativeRange = (dir: PeDataDirectory, rel: number, length: number): boolean =>
  Number.isSafeInteger(rel) && Number.isSafeInteger(length) && rel >= 0 && length >= 0 &&
  rel + length <= dir.size && isRvaRange(dir.rva + rel, Math.max(1, length));

const describeRelOffsetFailure = (
  dir: PeDataDirectory, resourceBase: number, fileSize: number, rvaToOff: RvaToOffset,
  rel: number, len: number, subject: string
): string => {
  if (!isResourceRelativeRange(dir, rel, len)) {
    return `${subject} lies outside the declared span.`;
  }
  const mappedOff = rvaToOff(dir.rva + rel);
  if (mappedOff != null && mappedOff >= 0 && mappedOff < fileSize &&
      mappedOff + len > fileSize) {
    return `${subject} is truncated by end of file.`;
  }
  const fallbackOff = resourceBase + rel;
  if (fallbackOff < fileSize && fallbackOff + len > fileSize) {
    return `${subject} is truncated by end of file.`;
  }
  return `${subject} could not be mapped within the declared resource span.`;
};

export const createResourceSpanResolver = (
  dir: PeDataDirectory,
  resourceBase: number,
  fileSize: number,
  rvaToOff: RvaToOffset
): ResourceSpanResolver => {
  const resolveRelOffset = (rel: number, len: number): number | null => {
    if (!isResourceRelativeRange(dir, rel, len)) return null;
    if (mappedRvaSize(rvaToOff, dir.rva + rel, len, fileSize) !== len) return null;
    return rvaToOff(dir.rva + rel);
  };
  return {
    readRelative: (view, rel, length) =>
      !Number.isSafeInteger(rel) || rel < 0 || rel >= dir.size ||
      !Number.isSafeInteger(length) || length <= 0
        ? Promise.resolve(new DataView(new ArrayBuffer(0)))
        : readMappedRvaPrefix({ size: fileSize, read: view },
          dir.rva + rel, Math.min(length, dir.size - rel), rvaToOff),
    formatRelOffset: formatResourceRelOffset,
    describeRelOffsetFailure: (rel, len, subject) =>
      describeRelOffsetFailure(dir, resourceBase, fileSize, rvaToOff, rel, len, subject),
    resolveRvaOffset: rva => mappedRvaSpan(rvaToOff, rva, 1, fileSize)?.offset ?? null,
    resolveRelOffset
  };
};
