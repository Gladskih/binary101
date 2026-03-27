"use strict";

import type { RvaToOffset } from "./types.js";

export interface ResourceSpanResolver {
  formatRelOffset: (rel: number) => string;
  describeRelOffsetFailure: (rel: number, len: number, subject: string) => string;
  resolveRelOffset: (rel: number, len: number) => number | null;
}

export const createResourceSpanResolver = (
  resourceRva: number,
  resourceSize: number,
  resourceBase: number,
  resourceLimitEnd: number,
  fileSize: number,
  rvaToOff: RvaToOffset
): ResourceSpanResolver => {
  const formatRelOffset = (rel: number): string => `0x${(rel >>> 0).toString(16)}`;
  const describeRelOffsetFailure = (rel: number, len: number, subject: string): string => {
    if (rel < 0 || len < 0 || rel + len > resourceSize) return `${subject} lies outside the declared span.`;
    const mappedOff = rvaToOff((resourceRva + rel) >>> 0);
    if (mappedOff != null && mappedOff >= 0 && mappedOff < fileSize && mappedOff + len > fileSize) {
      return `${subject} is truncated by end of file.`;
    }
    const fallbackOff = resourceBase + rel;
    if (fallbackOff >= resourceBase && fallbackOff < fileSize && fallbackOff + len > fileSize) {
      return `${subject} is truncated by end of file.`;
    }
    return `${subject} could not be mapped within the declared resource span.`;
  };
  const resolveRelOffset = (rel: number, len: number): number | null => {
    if (rel < 0 || len < 0 || rel + len > resourceSize) return null;
    const mappedOff = rvaToOff((resourceRva + rel) >>> 0);
    if (mappedOff != null && mappedOff >= 0 && mappedOff + len <= fileSize) {
      if (rel === 0 || mappedOff !== resourceBase) return mappedOff;
    }
    const fallbackOff = resourceBase + rel;
    if (fallbackOff < resourceBase || fallbackOff + len > resourceLimitEnd || fallbackOff + len > fileSize) {
      return null;
    }
    return fallbackOff;
  };
  return { formatRelOffset, describeRelOffsetFailure, resolveRelOffset };
};
