"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type { ElfCommentInfo, ElfSectionHeader } from "./types.js";

const toSafeIndex = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

export async function parseElfComment(file: File, sections: ElfSectionHeader[]): Promise<ElfCommentInfo | null> {
  const commentSection = sections.find(sec => sec.name === ".comment" && sec.size > 0n);
  if (!commentSection) return null;

  const issues: string[] = [];
  const start = toSafeIndex(commentSection.offset, ".comment offset", issues);
  const size = toSafeIndex(commentSection.size, ".comment size", issues);
  if (start == null || size == null || size <= 0) return { strings: [], issues };

  const end = Math.min(file.size, start + size);
  if (start >= file.size || end <= start) {
    issues.push(".comment falls outside the file.");
    return { strings: [], issues };
  }
  if (end !== start + size) issues.push(".comment is truncated.");
  const bytes = new Uint8Array(await file.slice(start, end).arrayBuffer());
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const strings: string[] = [];
  let offset = 0;
  while (offset < dv.byteLength) {
    const text = readAsciiString(dv, offset, dv.byteLength - offset);
    if (text.length) strings.push(text);
    offset += text.length + 1;
    while (offset < dv.byteLength && dv.getUint8(offset) === 0) offset += 1;
  }

  return { strings, issues };
}

