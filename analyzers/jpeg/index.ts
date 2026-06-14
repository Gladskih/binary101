"use strict";

import { readAsciiString } from "../../binary-utils.js";
import { parseExifFromApp1 } from "./exif.js";
import type {
  ExifData,
  JpegComment,
  JpegJfif,
  JpegParseResult,
  JpegSegment,
  JpegSof
} from "./types.js";

const MARKER_NAMES = new Map<number, string>([
  [0xffd8, "SOI (Start of Image)"],
  [0xffd9, "EOI (End of Image)"],
  [0xffc0, "SOF0 (Start of Frame, baseline)"],
  [0xffc1, "SOF1 (Start of Frame, extended)"],
  [0xffc2, "SOF2 (Start of Frame, progressive)"],
  [0xffc4, "DHT (Define Huffman Tables)"],
  [0xffdb, "DQT (Define Quantization Tables)"],
  [0xffdd, "DRI (Define Restart Interval)"],
  [0xffda, "SOS (Start of Scan)"],
  [0xffe0, "APP0 (JFIF application header)"],
  [0xffe1, "APP1 (EXIF/XMP metadata)"],
  [0xffe2, "APP2 (ICC color profile)"],
  [0xffed, "APP13 (Photoshop resources)"],
  [0xffee, "APP14 (Adobe-specific data)"],
  [0xfffe, "COM (Comment)"]
]);

const isRestartMarker = (marker: number): boolean => marker >= 0xffd0 && marker <= 0xffd7;

interface JpegScanState {
  offset: number;
  sof: JpegSof | null;
  hasExif: boolean;
  hasJfif: boolean;
  jfif: JpegJfif | null;
  hasIcc: boolean;
  hasAdobe: boolean;
  foundEoi: boolean;
  comments: JpegComment[];
  exif: ExifData | null;
}

function readUint16BE(dv: DataView, offset: number): number | null {
  if (offset + 2 > dv.byteLength) return null;
  return dv.getUint16(offset, false);
}

function scanForRarSignature(dv: DataView): boolean {
  if (dv.byteLength < 6) return false;
  const limit = dv.byteLength - 6;
  for (let i = 2; i <= limit; i += 1) {
    const r = dv.getUint8(i);
    if (r !== 0x52) continue;
    const a = dv.getUint8(i + 1);
    const rr = dv.getUint8(i + 2);
    const ex = dv.getUint8(i + 3);
    const b4 = dv.getUint8(i + 4);
    const b5 = dv.getUint8(i + 5);
    if (a === 0x61 && rr === 0x72 && ex === 0x21 && b4 === 0x1a && b5 === 0x07) {
      return true;
    }
  }
  return false;
}

function createInitialScanState(): JpegScanState {
  return {
    offset: 2,
    sof: null,
    hasExif: false,
    hasJfif: false,
    jfif: null,
    hasIcc: false,
    hasAdobe: false,
    foundEoi: false,
    comments: [],
    exif: null
  };
}

function readJpegSegments(dv: DataView): { segments: JpegSegment[]; state: JpegScanState } {
  const segments: JpegSegment[] = [];
  const state = createInitialScanState();
  while (state.offset + 2 <= dv.byteLength) {
    const marker = readUint16BE(dv, state.offset);
    if (marker == null || (marker & 0xff00) !== 0xff00) break;
    const markerOffset = state.offset;
    state.offset += 2;
    if (marker === 0xffd9) {
      segments.push({ marker, name: MARKER_NAMES.get(marker) || "EOI", offset: markerOffset, length: 2 });
      state.foundEoi = true;
      break;
    }
    if (marker === 0xff01 || isRestartMarker(marker)) {
      segments.push({ marker, name: MARKER_NAMES.get(marker) || "RST/ESC", offset: markerOffset, length: 2 });
      continue;
    }
    if (state.offset + 2 > dv.byteLength) break;
    const segLen = readUint16BE(dv, state.offset);
    if (segLen == null || segLen < 2 || state.offset + segLen > dv.byteLength) break;
    const seg = createSegment(dv, marker, markerOffset, segLen, state);
    segments.push(seg);
    state.offset += segLen;
    if (marker === 0xffda) break;
  }
  return { segments, state };
}

function createSegment(
  dv: DataView,
  marker: number,
  markerOffset: number,
  segLen: number,
  state: JpegScanState
): JpegSegment {
  const name = MARKER_NAMES.get(marker) || "Segment";
  const seg: JpegSegment = { marker, name, offset: markerOffset, length: 2 + segLen };
  if (marker >= 0xffc0 && marker <= 0xffc3 && segLen >= 8) readSofSegment(dv, marker, name, state.offset, state, seg);
  else if (marker === 0xffe0 && segLen >= 16) readJfifSegment(dv, state.offset, state, seg);
  else if (marker === 0xffe1 && segLen >= 8) readApp1Segment(dv, state.offset, state, seg);
  else if (marker === 0xffe2) state.hasIcc = true;
  else if (marker === 0xffee) state.hasAdobe = true;
  else if (marker === 0xfffe && segLen > 2) readCommentSegment(dv, state.offset, segLen, state, seg);
  return seg;
}

function readSofSegment(
  dv: DataView,
  marker: number,
  name: string,
  offset: number,
  state: JpegScanState,
  seg: JpegSegment
): void {
  state.sof = {
    marker,
    markerName: name,
    precision: dv.getUint8(offset + 2),
    width: readUint16BE(dv, offset + 5),
    height: readUint16BE(dv, offset + 3),
    components: dv.getUint8(offset + 7)
  };
  seg.info = state.sof;
}

function readJfifSegment(dv: DataView, offset: number, state: JpegScanState, seg: JpegSegment): void {
  const id = readAsciiString(dv, offset + 2, 5);
  seg.info = { id };
  if (!id.startsWith("JFIF")) return;
  state.hasJfif = true;
  if (state.jfif) return;
  state.jfif = {
    versionMajor: dv.getUint8(offset + 7),
    versionMinor: dv.getUint8(offset + 8),
    units: dv.getUint8(offset + 9),
    xDensity: readUint16BE(dv, offset + 10),
    yDensity: readUint16BE(dv, offset + 12),
    xThumbnail: dv.getUint8(offset + 14),
    yThumbnail: dv.getUint8(offset + 15)
  };
}

function readApp1Segment(dv: DataView, offset: number, state: JpegScanState, seg: JpegSegment): void {
  const id = readAsciiString(dv, offset + 2, 6);
  seg.info = { id };
  if (id.startsWith("Exif")) {
    state.hasExif = true;
    if (!state.exif && offset + 8 < dv.byteLength) state.exif = parseExifFromApp1(dv, offset + 8);
    return;
  }
  if (id.startsWith("http:")) state.hasExif = true;
}

function readCommentSegment(
  dv: DataView,
  offset: number,
  segLen: number,
  state: JpegScanState,
  seg: JpegSegment
): void {
  const maxCommentBytes = Math.min(segLen - 2, 256);
  const comment = readAsciiString(dv, offset + 2, maxCommentBytes);
  if (!comment) return;
  const commentInfo: JpegComment = { text: comment, truncated: segLen - 2 > maxCommentBytes };
  seg.info = commentInfo;
  state.comments.push(commentInfo);
}

export async function parseJpeg(file: File): Promise<JpegParseResult | null> {
  const buffer = await file.arrayBuffer();
  const dv = new DataView(buffer);
  const size = dv.byteLength;
  if (size < 4) return null;
  if (readUint16BE(dv, 0) !== 0xffd8) return null;
  const { segments, state } = readJpegSegments(dv);
  const hasRar = scanForRarSignature(dv);
  return {
    size,
    sof: state.sof,
    hasJfif: state.hasJfif,
    hasExif: state.hasExif,
    hasIcc: state.hasIcc,
    hasAdobe: state.hasAdobe,
    hasRar,
    hasEoi: state.foundEoi,
    segmentCount: segments.length,
    segments,
    comments: state.comments,
    jfif: state.jfif,
    exif: state.exif
  };
}
