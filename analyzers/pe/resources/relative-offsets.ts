"use strict";

import type { RvaToOffset } from "../types.js";
import type { PeDataDirectory } from "../types.js";

export interface ResourceSpanResolver {
  formatRelOffset: (rel: number) => string;
  describeRelOffsetFailure: (rel: number, len: number, subject: string) => string;
  resolveRvaOffset: (rva: number) => number | null;
  resolveRelOffset: (rel: number, len: number) => number | null;
}

export const formatResourceRelOffset = (rel: number): string => `0x${(rel >>> 0).toString(16)}`;

export const createResourceSpanResolver = (
  dir: PeDataDirectory,
  resourceBase: number,
  fileSize: number,
  rvaToOff: RvaToOffset
): ResourceSpanResolver => {
  const describeRelOffsetFailure = (rel: number, len: number, subject: string): string => {
    if (rel < 0 || len < 0 || rel + len > dir.size) {
      return `${subject} lies outside the declared span.`;
    }
    const mappedOff = rvaToOff((dir.rva + rel) >>> 0);
    if (
      mappedOff != null &&
      mappedOff >= 0 &&
      mappedOff < fileSize &&
      mappedOff + len > fileSize
    ) {
      return `${subject} is truncated by end of file.`;
    }
    const fallbackOff = resourceBase + rel;
    if (fallbackOff < fileSize && fallbackOff + len > fileSize) {
      return `${subject} is truncated by end of file.`;
    }
    return `${subject} could not be mapped within the declared resource span.`;
  };
  const resolveRelOffset = (rel: number, len: number): number | null => {
    if (rel < 0 || len < 0 || rel + len > dir.size) return null;
    const mappedOff = rvaToOff((dir.rva + rel) >>> 0);
    if (mappedOff != null && mappedOff >= 0 && mappedOff + len <= fileSize) {
      if (mappedOff !== resourceBase) return mappedOff;
    }
    const fallbackOff = resourceBase + rel;
    return fallbackOff + len <= fileSize ? fallbackOff : null;
  };
  return {
    formatRelOffset: formatResourceRelOffset,
    describeRelOffsetFailure,
    resolveRvaOffset: rvaToOff,
    resolveRelOffset
  };
};
