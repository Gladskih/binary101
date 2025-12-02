"use strict";

import { readBoxHeaderFromView } from "./boxes.js";
import { parseStsd } from "./sample-description.js";
import type { Mp4CodecDetails } from "./types.js";

export type SttsInfo = {
  sampleCount: number;
  totalDuration: number;
};

export type StszInfo = {
  sampleSizeConstant: number | null;
  sampleCount: number | null;
};

export type StcoInfo = {
  chunkCount: number | null;
};

export type StssInfo = {
  keyframeCount: number | null;
};

export type TrackTables = {
  stts: SttsInfo | null;
  stsz: StszInfo | null;
  stco: StcoInfo | null;
  stss: StssInfo | null;
};

export const parseStts = (view: DataView, start: number, size: number, issues: string[]): SttsInfo | null => {
  if (size < 8) {
    issues.push("stts box truncated.");
    return null;
  }
  const entryCount = view.getUint32(start + 4, false);
  let offset = start + 8;
  let sampleCount = 0;
  let totalDuration = 0;
  for (let i = 0; i < entryCount; i += 1) {
    if (offset + 8 > start + size) {
      issues.push("stts entries truncated.");
      break;
    }
    const count = view.getUint32(offset, false);
    const delta = view.getUint32(offset + 4, false);
    sampleCount += count;
    totalDuration += count * delta;
    offset += 8;
  }
  return { sampleCount, totalDuration };
};

export const parseStsz = (view: DataView, start: number, size: number, issues: string[]): StszInfo | null => {
  if (size < 12) {
    issues.push("stsz box truncated.");
    return null;
  }
  const sampleSize = view.getUint32(start + 4, false);
  const sampleCount = view.getUint32(start + 8, false);
  if (sampleSize === 0) {
    const tableBytes = sampleCount * 4;
    if (start + 12 + tableBytes > start + size) {
      issues.push("stsz sample size table truncated.");
    }
  }
  return { sampleSizeConstant: sampleSize || null, sampleCount };
};

export const parseStco = (view: DataView, start: number, size: number, issues: string[]): StcoInfo | null => {
  if (size < 8) {
    issues.push("stco box truncated.");
    return null;
  }
  const entryCount = view.getUint32(start + 4, false);
  const required = entryCount * 4;
  if (start + 8 + required > start + size) {
    issues.push("stco entries truncated.");
  }
  return { chunkCount: entryCount };
};

export const parseCo64 = (view: DataView, start: number, size: number, issues: string[]): StcoInfo | null => {
  if (size < 8) {
    issues.push("co64 box truncated.");
    return null;
  }
  const entryCount = view.getUint32(start + 4, false);
  const required = entryCount * 8;
  if (start + 8 + required > start + size) {
    issues.push("co64 entries truncated.");
  }
  return { chunkCount: entryCount };
};

export const parseStss = (view: DataView, start: number, size: number, issues: string[]): StssInfo | null => {
  if (size < 8) {
    issues.push("stss box truncated.");
    return null;
  }
  const entryCount = view.getUint32(start + 4, false);
  const required = entryCount * 4;
  if (start + 8 + required > start + size) {
    issues.push("stss entries truncated.");
  }
  return { keyframeCount: entryCount };
};

export const parseStbl = (
  view: DataView,
  start: number,
  size: number,
  handlerType: string | null,
  issues: string[]
): { codec: Mp4CodecDetails | null; tables: TrackTables } => {
  let offset = start;
  const end = start + size;
  let codec: Mp4CodecDetails | null = null;
  const tables: TrackTables = { stts: null, stsz: null, stco: null, stss: null };
  while (offset + 8 <= end) {
    const header = readBoxHeaderFromView(view, offset, view.byteOffset + offset, issues);
    if (!header || header.start >= header.end) break;
    const payloadStart = offset + header.headerSize;
    const payloadSize = header.size - header.headerSize;
    if (header.type === "stsd") {
      codec = parseStsd(view, payloadStart, payloadSize, handlerType, issues) || codec;
    } else if (header.type === "stts") {
      tables.stts = parseStts(view, payloadStart, payloadSize, issues);
    } else if (header.type === "stsz") {
      tables.stsz = parseStsz(view, payloadStart, payloadSize, issues);
    } else if (header.type === "stco") {
      tables.stco = parseStco(view, payloadStart, payloadSize, issues);
    } else if (header.type === "co64") {
      tables.stco = parseCo64(view, payloadStart, payloadSize, issues);
    } else if (header.type === "stss") {
      tables.stss = parseStss(view, payloadStart, payloadSize, issues);
    }
    offset += header.size;
  }
  return { codec, tables };
};

export const parseMinf = (
  view: DataView,
  start: number,
  size: number,
  handlerType: string | null,
  issues: string[]
): { codec: Mp4CodecDetails | null; tables: TrackTables } => {
  let offset = start;
  const end = start + size;
  let codec: Mp4CodecDetails | null = null;
  const tables: TrackTables = { stts: null, stsz: null, stco: null, stss: null };
  while (offset + 8 <= end) {
    const header = readBoxHeaderFromView(view, offset, view.byteOffset + offset, issues);
    if (!header || header.start >= header.end) break;
    const payloadStart = offset + header.headerSize;
    const payloadSize = header.size - header.headerSize;
    if (header.type === "stbl") {
      const stbl = parseStbl(view, payloadStart, payloadSize, handlerType, issues);
      codec = stbl.codec || codec;
      tables.stts = stbl.tables.stts || tables.stts;
      tables.stsz = stbl.tables.stsz || tables.stsz;
      tables.stco = stbl.tables.stco || tables.stco;
      tables.stss = stbl.tables.stss || tables.stss;
    }
    offset += header.size;
  }
  return { codec, tables };
};
