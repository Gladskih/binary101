"use strict";

import {
  findFirstChunk,
  parseInfoTags,
  parseRiffFromView
} from "../riff/index.js";
import { parseWaveFormat } from "../riff/wave-format.js";
import type { WavParseResult } from "./types.js";

const toDurationSeconds = (size: number, byteRate: number | null): number | null => {
  if (!byteRate || byteRate <= 0) return null;
  const seconds = size / byteRate;
  return Number.isFinite(seconds) ? Math.round(seconds * 1000) / 1000 : null;
};

export async function parseWav(file: File): Promise<WavParseResult | null> {
  const dv = new DataView(await file.arrayBuffer());
  const riff = parseRiffFromView(dv, { maxChunks: 8192, maxDepth: 4 });
  if (!riff || riff.formType !== "WAVE") return null;
  const issues = [...riff.issues];

  const fmtChunk = findFirstChunk(riff.chunks, "fmt ");
  let format = null;
  if (!fmtChunk) {
    issues.push("Missing fmt chunk.");
  } else if (fmtChunk.truncated) {
    issues.push("fmt chunk is truncated.");
  } else {
    format = parseWaveFormat(
      dv,
      fmtChunk.dataOffset,
      fmtChunk.size,
      riff.littleEndian,
      issues
    );
  }

  const dataChunk = findFirstChunk(riff.chunks, "data");
  let data = null;
  if (dataChunk) {
    const durationSeconds = toDurationSeconds(
      dataChunk.size,
      format?.byteRate ?? null
    );
    data = {
      size: dataChunk.size,
      offset: dataChunk.dataOffset,
      durationSeconds,
      truncated: dataChunk.truncated
    };
    if (data.truncated) issues.push("data chunk is truncated.");
  } else {
    issues.push("Missing data chunk.");
  }

  const factChunk = findFirstChunk(riff.chunks, "fact");
  let factSampleLength: number | null = null;
  if (factChunk) {
    if (factChunk.truncated || factChunk.dataOffset + 4 > dv.byteLength) {
      issues.push("fact chunk is truncated.");
    } else if (factChunk.size >= 4) {
      factSampleLength = dv.getUint32(factChunk.dataOffset, riff.littleEndian);
    }
  }

  const infoTags = parseInfoTags(dv, riff);

  return { riff, format, data, factSampleLength, infoTags, issues };
}
