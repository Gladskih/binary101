"use strict";

import { readAsciiString } from "../../binary-utils.js";
import { parseExifFromApp1 } from "./exif.js";

const MARKER_NAMES = new Map([
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

const isRestartMarker = marker => marker >= 0xffd0 && marker <= 0xffd7;

function readUint16BE(dv, offset) {
  if (offset + 2 > dv.byteLength) return null;
  return dv.getUint16(offset, false);
}

function scanForRarSignature(dv) {
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
    if (
      a === 0x61 &&
      rr === 0x72 &&
      ex === 0x21 &&
      b4 === 0x1a &&
      b5 === 0x07
    ) {
      return true;
    }
  }
  return false;
}

export async function parseJpeg(file) {
  const buffer = await file.arrayBuffer();
  const dv = new DataView(buffer);
  const size = dv.byteLength;
  if (size < 4) return null;
  if (readUint16BE(dv, 0) !== 0xffd8) return null;

  const segments = [];
  let offset = 2;
  let sof = null;
  let hasExif = false;
  let hasJfif = false;
  let jfif = null;
  let hasIcc = false;
  let hasAdobe = false;
  let foundEoi = false;
  const comments = [];
  let exif = null;

  while (offset + 2 <= size) {
    const marker = readUint16BE(dv, offset);
    if (marker == null || (marker & 0xff00) !== 0xff00) break;
    const markerOffset = offset;
    offset += 2;
    if (marker === 0xffd9) {
      segments.push({
        marker,
        name: MARKER_NAMES.get(marker) || "EOI",
        offset: markerOffset,
        length: 2
      });
      foundEoi = true;
      break;
    }
    if (marker === 0xff01 || isRestartMarker(marker)) {
      segments.push({
        marker,
        name: MARKER_NAMES.get(marker) || "RST/ESC",
        offset: markerOffset,
        length: 2
      });
      continue;
    }
    if (offset + 2 > size) break;
    const segLen = readUint16BE(dv, offset);
    if (!segLen || segLen < 2 || offset + segLen > size) break;
    const segStart = markerOffset;
    const segTotalLen = 2 + segLen;

    const name = MARKER_NAMES.get(marker) || "Segment";
    const seg = {
      marker,
      name,
      offset: segStart,
      length: segTotalLen
    };

    if (marker >= 0xffc0 && marker <= 0xffc3 && segLen >= 8) {
      const precision = dv.getUint8(offset + 2);
      const height = readUint16BE(dv, offset + 3);
      const width = readUint16BE(dv, offset + 5);
      const components = dv.getUint8(offset + 7);
      sof = {
        marker,
        markerName: name,
        precision,
        width,
        height,
        components
      };
      seg.info = sof;
    } else if (marker === 0xffe0 && segLen >= 16) {
      const id = readAsciiString(dv, offset + 2, 5);
      seg.info = { id };
      if (id.startsWith("JFIF")) {
        hasJfif = true;
        if (!jfif) {
          const versionMajor = dv.getUint8(offset + 7);
          const versionMinor = dv.getUint8(offset + 8);
          const units = dv.getUint8(offset + 9);
          const xDensity = readUint16BE(dv, offset + 10);
          const yDensity = readUint16BE(dv, offset + 12);
          const xThumbnail = dv.getUint8(offset + 14);
          const yThumbnail = dv.getUint8(offset + 15);
          jfif = {
            versionMajor,
            versionMinor,
            units,
            xDensity,
            yDensity,
            xThumbnail,
            yThumbnail
          };
        }
      }
    } else if (marker === 0xffe1 && segLen >= 8) {
      const id = readAsciiString(dv, offset + 2, 6);
      seg.info = { id };
      if (id.startsWith("Exif")) {
        hasExif = true;
        if (!exif) {
          const tiffOffset = offset + 2 + 6;
          if (tiffOffset < dv.byteLength) {
            exif = parseExifFromApp1(dv, tiffOffset);
          }
        }
      } else if (id.startsWith("http:")) {
        hasExif = true;
      }
    } else if (marker === 0xffe2) {
      hasIcc = true;
    } else if (marker === 0xffee) {
      hasAdobe = true;
    } else if (marker === 0xfffe && segLen > 2) {
      const maxCommentBytes = Math.min(segLen - 2, 256);
      const comment = readAsciiString(dv, offset + 2, maxCommentBytes);
      if (comment) {
        const commentInfo = {
          text: comment,
          truncated: segLen - 2 > maxCommentBytes
        };
        seg.info = commentInfo;
        comments.push(commentInfo);
      }
    }

    segments.push(seg);

    offset += segLen;
    if (marker === 0xffda) break;
  }

  const hasRar = scanForRarSignature(dv);

  return {
    size,
    sof,
    hasJfif,
    hasExif,
    hasIcc,
    hasAdobe,
    hasRar,
    hasEoi: foundEoi,
    segmentCount: segments.length,
    segments,
    comments,
    jfif,
    exif
  };
}
