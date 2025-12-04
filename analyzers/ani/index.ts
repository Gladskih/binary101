"use strict";

import {
  findFirstChunk,
  flattenChunks,
  parseInfoTags,
  parseRiffFromView
} from "../riff/index.js";
import type { AniHeader, AniParseResult } from "./types.js";

const ANI_HEADER_SIZE = 36;
const MAX_LIST_ITEMS = 1024;

const parseAniHeader = (
  dv: DataView,
  chunkOffset: number,
  chunkSize: number,
  littleEndian: boolean,
  issues: string[]
): AniHeader | null => {
  if (chunkSize < ANI_HEADER_SIZE || chunkOffset + ANI_HEADER_SIZE > dv.byteLength) {
    issues.push("anih chunk is truncated.");
    return null;
  }
  const read32 = (rel: number) => dv.getUint32(chunkOffset + rel, littleEndian);
  const cbSizeof = read32(0);
  if (cbSizeof && cbSizeof > chunkSize) {
    issues.push("anih declares a header larger than the chunk size.");
  }
  const jifRate = read32(28);
  const defaultFps = jifRate > 0 ? Math.round((60 / jifRate) * 1000) / 1000 : null;
  const flags = read32(32);
  const flagNotes: string[] = [];
  if ((flags & 0x1) !== 0) flagNotes.push("Frames stored as ICO/CUR (ANI_FLAG_ICON)");
  if ((flags & 0x2) !== 0) flagNotes.push("Sequence chunk is required (ANI_FLAG_SEQUENCE)");
  return {
    frameCount: read32(4),
    stepCount: read32(8),
    width: read32(12),
    height: read32(16),
    bitCount: read32(20),
    planes: read32(24),
    jifRate,
    defaultFps,
    flags,
    flagNotes
  };
};

const parseUint32Array = (
  dv: DataView,
  chunkOffset: number,
  chunkSize: number,
  littleEndian: boolean,
  label: string,
  issues: string[]
): number[] => {
  const count = Math.min(Math.floor(chunkSize / 4), MAX_LIST_ITEMS);
  const values: number[] = [];
  for (let i = 0; i < count && chunkOffset + (i + 1) * 4 <= dv.byteLength; i += 1) {
    values.push(dv.getUint32(chunkOffset + i * 4, littleEndian));
  }
  if (chunkSize / 4 > MAX_LIST_ITEMS) {
    issues.push(`${label} list truncated after ${MAX_LIST_ITEMS} entries.`);
  }
  return values;
};

export async function parseAni(file: File): Promise<AniParseResult | null> {
  const dv = new DataView(await file.arrayBuffer());
  const riff = parseRiffFromView(dv, { maxChunks: 4096, maxDepth: 4 });
  if (!riff || riff.formType !== "ACON") return null;
  const issues = [...riff.issues];

  const anih = findFirstChunk(riff.chunks, "anih");
  const header = anih
    ? parseAniHeader(dv, anih.dataOffset, anih.size, riff.littleEndian, issues)
    : null;
  if (!anih) issues.push("Missing anih header chunk.");

  const rateChunk = findFirstChunk(riff.chunks, "rate");
  const rates =
    rateChunk && !rateChunk.truncated
      ? parseUint32Array(
          dv,
          rateChunk.dataOffset,
          rateChunk.size,
          riff.littleEndian,
          "rate",
          issues
        )
      : [];
  if (rateChunk?.truncated) issues.push("rate chunk is truncated.");

  const seqChunk = findFirstChunk(riff.chunks, "seq ");
  const sequence =
    seqChunk && !seqChunk.truncated
      ? parseUint32Array(
          dv,
          seqChunk.dataOffset,
          seqChunk.size,
          riff.littleEndian,
          "seq",
          issues
        )
      : [];
  if (seqChunk?.truncated) issues.push("seq chunk is truncated.");

  const flatChunks = flattenChunks(riff.chunks);
  const frames = flatChunks.filter(chunk => {
    const id = (chunk.id || "").toLowerCase();
    return id === "icon" || id === "fram";
  }).length;

  const infoTags = parseInfoTags(dv, riff);

  return { riff, header, rates, sequence, frames, infoTags, issues };
}
