"use strict";

import type { Mp4BoxSummary, Mp4BrandInfo, Mp4MovieHeader, Mp4ParseResult, Mp4Track } from "./types.js";
import { readBoxHeaderFromFile, readBoxHeaderFromView, toFourCcFromView } from "./boxes.js";
import type { BoxHeader } from "./boxes.js";
import { parseMvhd } from "./movie-header.js";
import { parseTrak } from "./track.js";

const parseFtyp = async (file: File, header: BoxHeader, issues: string[]): Promise<Mp4BrandInfo | null> => {
  const length = header.end - header.dataOffset;
  const buffer = await file.slice(header.dataOffset, header.end).arrayBuffer();
  const dv = new DataView(buffer);
  if (length < 8) {
    issues.push("ftyp box is too small to read brands.");
    return null;
  }
  const majorBrand = toFourCcFromView(dv, 0) || null;
  const minorVersion = dv.getUint32(4, false);
  const compatibleBrands: string[] = [];
  for (let offset = 8; offset + 4 <= dv.byteLength; offset += 4) {
    const brand = toFourCcFromView(dv, offset);
    if (brand) compatibleBrands.push(brand);
  }
  return { majorBrand, minorVersion, compatibleBrands };
};

const parseMoov = async (
  file: File,
  header: BoxHeader,
  issues: string[]
): Promise<{ mvhd: Mp4MovieHeader | null; tracks: Mp4Track[] }> => {
  const buffer = await file.slice(header.dataOffset, header.end).arrayBuffer();
  const view = new DataView(buffer);
  let offset = 0;
  let mvhd: Mp4MovieHeader | null = null;
  const tracks: Mp4Track[] = [];
  while (offset + 8 <= view.byteLength) {
    const child = readBoxHeaderFromView(view, offset, header.dataOffset + offset, issues);
    if (!child || child.start >= child.end) break;
    const payloadStart = offset + child.headerSize;
    const payloadSize = child.size - child.headerSize;
    if (child.type === "mvhd") {
      mvhd = parseMvhd(view, payloadStart, payloadSize, issues) || mvhd;
    } else if (child.type === "trak") {
      const track = parseTrak(view, payloadStart, payloadSize, issues);
      if (track) tracks.push(track);
    }
    offset += child.size;
  }
  return { mvhd, tracks };
};

export async function parseMp4(file: File): Promise<Mp4ParseResult | null> {
  if (file.size < 12) return null;
  const prefix = new DataView(await file.slice(0, Math.min(file.size, 64)).arrayBuffer());
  const firstType = prefix.getUint32(4, false);
  if (firstType !== 0x66747970) return null;
  const issues: string[] = [];
  const topLevelBoxes: Mp4BoxSummary[] = [];
  let brands: Mp4BrandInfo | null = null;
  let movieHeader: Mp4MovieHeader | null = null;
  const tracks: Mp4Track[] = [];
  let fragmentCount = 0;
  let mdatBytes = 0;
  let firstMoovOffset: number | null = null;
  let firstMdatOffset: number | null = null;

  let offset = 0;
  while (offset + 8 <= file.size) {
    const header = await readBoxHeaderFromFile(file, offset, issues, "MP4");
    if (!header) break;
    topLevelBoxes.push({
      type: header.type,
      start: header.start,
      end: header.end,
      size: header.size,
      headerSize: header.headerSize,
      largesize: header.largesize ?? null,
      truncated: header.truncated === true
    });
    if (header.type === "ftyp" && !brands) {
      brands = await parseFtyp(file, header, issues);
    } else if (header.type === "moov") {
      firstMoovOffset = firstMoovOffset ?? header.start;
      const moov = await parseMoov(file, header, issues);
      movieHeader = moov.mvhd || movieHeader;
      tracks.push(...moov.tracks);
    } else if (header.type === "moof") {
      fragmentCount += 1;
    } else if (header.type === "mdat") {
      if (firstMdatOffset == null) firstMdatOffset = header.start;
      mdatBytes += header.size;
    }
    if (!header.size) break;
    offset = header.end;
  }

  const fastStart =
    firstMoovOffset != null && firstMdatOffset != null
      ? firstMoovOffset < firstMdatOffset
      : null;

  if (!movieHeader) issues.push("Movie header not found.");
  if (tracks.length === 0) issues.push("No tracks were parsed from this file.");

  return {
    isMp4: true,
    brands,
    movieHeader,
    tracks,
    fragmentCount,
    mdatBytes,
    fastStart,
    topLevelBoxes,
    warnings: issues
  };
}

export const buildMp4Label = (parsed: Mp4ParseResult | null | undefined): string | null => {
  if (!parsed) return null;
  const brand = parsed.brands?.majorBrand || "MP4";
  const video = parsed.tracks.find(track => track.kind === "video");
  const audio = parsed.tracks.find(track => track.kind === "audio");
  const parts: string[] = [];
  if (video) {
    const videoParts: string[] = [];
    if (video.codec?.codecString) videoParts.push(video.codec.codecString);
    if (!videoParts.length && video.codec?.description) videoParts.push(video.codec.description);
    if (video.width && video.height) videoParts.push(`${video.width}x${video.height}`);
    parts.push(`video: ${videoParts.join(", ") || "track"}`);
  }
  if (audio) {
    const audioParts: string[] = [];
    if (audio.codec?.codecString) audioParts.push(audio.codec.codecString);
    if (!audioParts.length && audio.codec?.description) audioParts.push(audio.codec.description);
    if (audio.codec?.sampleRate) audioParts.push(`${Math.round(audio.codec.sampleRate)} Hz`);
    if (audio.codec?.channels) audioParts.push(`${audio.codec.channels} ch`);
    parts.push(`audio: ${audioParts.join(", ") || "track"}`);
  }
  const duration =
    parsed.movieHeader?.durationSeconds ??
    video?.durationSeconds ??
    audio?.durationSeconds ??
    null;
  const durationLabel =
    duration != null ? `${(Math.round(duration * 1000) / 1000).toFixed(duration < 10 ? 3 : 1)} s` : null;
  if (durationLabel) parts.push(durationLabel);
  const suffix = parts.length ? ` (${parts.join("; ")})` : "";
  return `${brand} MP4${suffix}`;
};
