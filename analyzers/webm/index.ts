"use strict";

import {
  EBML_ID,
  SEGMENT_ID
} from "./constants.js";
import { readElementAt } from "./ebml.js";
import { parseEbmlHeader, validateDocTypeCompatibility } from "./info.js";
import { parseSegment } from "./segment.js";
import type { WebmParseResult } from "./types.js";

export async function parseWebm(file: File): Promise<WebmParseResult | null> {
  if (file.size < 4) return null;
  const prefix = new DataView(await file.slice(0, Math.min(file.size, 1024)).arrayBuffer());
  if (prefix.getUint32(0, false) !== EBML_ID) return null;
  const issues: string[] = [];
  const ebmlHeader = await readElementAt(file, 0, issues);
  if (!ebmlHeader || ebmlHeader.id !== EBML_ID) return null;
  const { ebmlHeader: headerInfo, docType } = await parseEbmlHeader(file, ebmlHeader, issues);
  const docTypeLower = docType ? docType.toLowerCase() : "";
  validateDocTypeCompatibility(issues, docTypeLower, headerInfo);
  const segmentOffset =
    ebmlHeader.size != null ? ebmlHeader.dataOffset + ebmlHeader.size : ebmlHeader.dataOffset;
  const segmentHeader = await readElementAt(file, segmentOffset, issues);
  if (!segmentHeader || segmentHeader.id !== SEGMENT_ID) {
    issues.push("Segment element not found after EBML header.");
    return {
      isWebm: docTypeLower === "webm",
      isMatroska: docTypeLower === "matroska",
      docType: docType || null,
      ebmlHeader: headerInfo,
      segment: null,
      issues
    };
  }
  const segment = await parseSegment(file, segmentHeader, issues, docTypeLower);
  return {
    isWebm: docTypeLower === "webm",
    isMatroska: docTypeLower === "matroska",
    docType: docType || null,
    ebmlHeader: headerInfo,
    segment,
    issues
  };
}

export const buildWebmLabel = (parsed: WebmParseResult | null | undefined): string | null => {
  if (!parsed || !parsed.segment) return null;
  const prefix = parsed.isWebm
    ? "WebM"
    : parsed.isMatroska
      ? "Matroska"
      : parsed.docType
        ? `Matroska (${parsed.docType})`
        : "Matroska/WebM";
  const tracks = parsed.segment.tracks || [];
  const video = tracks.find(track => track.trackType === 1);
  const audio = tracks.find(track => track.trackType === 2);
  const parts: string[] = [];
  if (video) {
    const videoParts: string[] = [];
    if (video.codecId) videoParts.push(video.codecId);
    if (video.video?.pixelWidth && video.video?.pixelHeight) {
      videoParts.push(`${video.video.pixelWidth}x${video.video.pixelHeight}`);
    }
    if (video.defaultDurationFps) videoParts.push(`${video.defaultDurationFps} fps`);
    parts.push(`video: ${videoParts.join(", ") || "track"}`);
  }
  if (audio) {
    const audioParts: string[] = [];
    if (audio.codecId) audioParts.push(audio.codecId);
    if (audio.audio?.samplingFrequency) {
      const rate = Math.round(audio.audio.samplingFrequency);
      audioParts.push(`${rate} Hz`);
    }
    if (audio.audio?.channels) audioParts.push(`${audio.audio.channels} ch`);
    parts.push(`audio: ${audioParts.join(", ") || "track"}`);
  }
  const suffix = parts.length ? ` (${parts.join("; ")})` : "";
  return `${prefix}${suffix}`;
};
