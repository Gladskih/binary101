"use strict";

import {
  parseLanguage,
  parseCreationTime,
  readBoxHeaderFromView,
  readFixed1616,
  readFixed88,
  readUint16Safe,
  toFourCcFromView
} from "./boxes.js";
import { parseMinf } from "./sample-tables.js";
import type { TrackTables } from "./sample-tables.js";
import type { Mp4CodecDetails, Mp4Track, Mp4TrackKind } from "./types.js";

type ParsedHdlr = {
  handlerType: string | null;
  handlerName: string | null;
};

type ParsedMdhd = {
  creationTime: string | null;
  modificationTime: string | null;
  timescale: number | null;
  duration: number | null;
  durationSeconds: number | null;
  language: string | null;
};

type ParsedTkhd = {
  id: number | null;
  duration: number | null;
  durationSeconds: number | null;
  width: number | null;
  height: number | null;
  volume: number | null;
  creationTime: string | null;
  modificationTime: string | null;
};

export const parseTkhd = (view: DataView, start: number, size: number, issues: string[]): ParsedTkhd | null => {
  if (size < 20) {
    issues.push("tkhd box truncated.");
    return null;
  }
  const version = view.getUint8(start);
  let cursor = start + 4;
  let creation: number | null = null;
  let modification: number | null = null;
  let duration: number | null = null;
  let trackId: number | null = null;
  if (version === 1) {
    if (cursor + 28 > start + size) {
      issues.push("tkhd version 1 box truncated.");
      return null;
    }
    creation = Number(view.getBigUint64(cursor, false));
    cursor += 8;
    modification = Number(view.getBigUint64(cursor, false));
    cursor += 8;
    trackId = view.getUint32(cursor, false);
    cursor += 4;
    cursor += 4; // reserved
    duration = Number(view.getBigUint64(cursor, false));
    cursor += 8;
  } else {
    if (cursor + 16 > start + size) {
      issues.push("tkhd version 0 box truncated.");
      return null;
    }
    creation = view.getUint32(cursor, false);
    cursor += 4;
    modification = view.getUint32(cursor, false);
    cursor += 4;
    trackId = view.getUint32(cursor, false);
    cursor += 4;
    cursor += 4; // reserved
    duration = view.getUint32(cursor, false);
    cursor += 4;
  }
  cursor += 8; // reserved[2]
  cursor += 2; // layer
  cursor += 2; // alternate group
  const volume = readFixed88(view.getUint16(cursor, false));
  cursor += 2;
  cursor += 2; // reserved
  cursor += 36; // matrix
  const width = readFixed1616(view.getUint32(cursor, false));
  cursor += 4;
  const height = readFixed1616(view.getUint32(cursor, false));
  return {
    id: trackId || null,
    duration,
    durationSeconds: null,
    width,
    height,
    volume,
    creationTime: parseCreationTime(creation),
    modificationTime: parseCreationTime(modification)
  };
};

export const parseMdhd = (view: DataView, start: number, size: number, issues: string[]): ParsedMdhd | null => {
  if (size < 12) {
    issues.push("mdhd box truncated.");
    return null;
  }
  const version = view.getUint8(start);
  let offset = start + 4;
  let creation: number | null = null;
  let modification: number | null = null;
  let timescale: number | null = null;
  let duration: number | null = null;
  if (version === 1) {
    if (offset + 28 > start + size) {
      issues.push("mdhd version 1 box truncated.");
      return null;
    }
    creation = Number(view.getBigUint64(offset, false));
    modification = Number(view.getBigUint64(offset + 8, false));
    timescale = view.getUint32(offset + 16, false);
    duration = Number(view.getBigUint64(offset + 20, false));
    offset += 28;
  } else {
    if (offset + 12 > start + size) {
      issues.push("mdhd version 0 box truncated.");
      return null;
    }
    creation = view.getUint32(offset, false);
    modification = view.getUint32(offset + 4, false);
    timescale = view.getUint32(offset + 8, false);
    duration = view.getUint32(offset + 12, false);
    offset += 16;
  }
  const languageCode = readUint16Safe(view, offset);
  const language = parseLanguage(languageCode);
  const durationSeconds = timescale && duration != null ? duration / timescale : null;
  return {
    creationTime: parseCreationTime(creation),
    modificationTime: parseCreationTime(modification),
    timescale: timescale ?? null,
    duration,
    durationSeconds,
    language
  };
};

export const parseHdlr = (view: DataView, start: number, size: number, issues: string[]): ParsedHdlr | null => {
  if (size < 12) {
    issues.push("hdlr box truncated.");
    return null;
  }
  const handlerType = toFourCcFromView(view, start + 8) || null;
  const nameOffset = start + 24;
  let handlerName: string | null = null;
  if (nameOffset < start + size) {
    const slice = new Uint8Array(view.buffer, view.byteOffset + nameOffset, Math.max(0, size - 24));
    const nullIndex = slice.indexOf(0);
    const text = new TextDecoder().decode(nullIndex === -1 ? slice : slice.slice(0, nullIndex));
    handlerName = text || null;
  }
  return { handlerType, handlerName };
};

export const parseMdia = (view: DataView, start: number, size: number, issues: string[]): {
  mdhd: ParsedMdhd | null;
  hdlr: ParsedHdlr | null;
  codec: Mp4CodecDetails | null;
  tables: TrackTables;
} => {
  let offset = start;
  const end = start + size;
  let mdhd: ParsedMdhd | null = null;
  let hdlr: ParsedHdlr | null = null;
  let codec: Mp4CodecDetails | null = null;
  const tables: TrackTables = { stts: null, stsz: null, stco: null, stss: null };
  while (offset + 8 <= end) {
    const header = readBoxHeaderFromView(view, offset, view.byteOffset + offset, issues);
    if (!header || header.start >= header.end) break;
    const payloadStart = offset + header.headerSize;
    const payloadSize = header.size - header.headerSize;
    if (header.type === "mdhd") {
      mdhd = parseMdhd(view, payloadStart, payloadSize, issues);
    } else if (header.type === "hdlr") {
      hdlr = parseHdlr(view, payloadStart, payloadSize, issues);
    } else if (header.type === "minf") {
      const minf = parseMinf(view, payloadStart, payloadSize, hdlr?.handlerType ?? null, issues);
      codec = minf.codec || codec;
      tables.stts = minf.tables.stts || tables.stts;
      tables.stsz = minf.tables.stsz || tables.stsz;
      tables.stco = minf.tables.stco || tables.stco;
      tables.stss = minf.tables.stss || tables.stss;
    }
    offset += header.size;
  }
  return { mdhd, hdlr, codec, tables };
};

export const parseTrak = (view: DataView, start: number, size: number, _issues: string[]): Mp4Track | null => {
  const trackIssues: string[] = [];
  let offset = start;
  const end = start + size;
  let tkhd: ParsedTkhd | null = null;
  let mdia: ReturnType<typeof parseMdia> | null = null;
  while (offset + 8 <= end) {
    const header = readBoxHeaderFromView(view, offset, view.byteOffset + offset, trackIssues);
    if (!header || header.start >= header.end) break;
    const payloadStart = offset + header.headerSize;
    const payloadSize = header.size - header.headerSize;
    if (header.type === "tkhd") {
      tkhd = parseTkhd(view, payloadStart, payloadSize, trackIssues);
    } else if (header.type === "mdia") {
      mdia = parseMdia(view, payloadStart, payloadSize, trackIssues);
    }
    offset += header.size;
  }
  if (!tkhd && !mdia) return null;
  const handlerType = mdia?.hdlr?.handlerType || null;
  const kind: Mp4TrackKind =
    handlerType === "vide"
      ? "video"
      : handlerType === "soun"
        ? "audio"
        : handlerType === "hint"
          ? "hint"
          : handlerType === "subt"
            ? "subtitles"
            : handlerType === "text"
              ? "text"
              : handlerType === "meta"
                ? "meta"
                : "unknown";
  const timescale = mdia?.mdhd?.timescale ?? null;
  const durationRaw = mdia?.mdhd?.duration ?? tkhd?.duration ?? null;
  const durationSeconds =
    mdia?.mdhd?.durationSeconds ??
    (timescale && durationRaw != null ? durationRaw / timescale : null);
  const width = tkhd?.width ?? mdia?.codec?.width ?? null;
  const height = tkhd?.height ?? mdia?.codec?.height ?? null;
  const language = mdia?.mdhd?.language ?? null;
  const sampleCount = mdia?.tables.stts?.sampleCount ?? mdia?.tables.stsz?.sampleCount ?? null;
  const keyframeCount = mdia?.tables.stss?.keyframeCount ?? null;
  const chunkCount = mdia?.tables.stco?.chunkCount ?? null;
  const sampleSizeConstant = mdia?.tables.stsz?.sampleSizeConstant ?? null;
  return {
    id: tkhd?.id ?? null,
    kind,
    handlerType,
    handlerName: mdia?.hdlr?.handlerName ?? null,
    creationTime: mdia?.mdhd?.creationTime ?? tkhd?.creationTime ?? null,
    modificationTime: mdia?.mdhd?.modificationTime ?? tkhd?.modificationTime ?? null,
    duration: durationRaw,
    durationSeconds,
    timescale,
    language,
    width,
    height,
    volume: tkhd?.volume ?? null,
    sampleCount,
    keyframeCount,
    chunkCount,
    sampleSizeConstant,
    codec: mdia?.codec ?? null,
    warnings: trackIssues
  };
};
