"use strict";
import { readAsciiString } from "../../binary-utils.js";
import type { ExifData, ExifGps, ExifRational, ExifRawTag } from "./types.js";
const EXIF_TYPE_SIZE: Record<number, number> = {
  1: 1, // BYTE
  2: 1, // ASCII
  3: 2, // SHORT
  4: 4, // LONG
  5: 8 // RATIONAL
};
interface ExifParsingState {
  dv: DataView; tiffOffset: number; littleEndian: boolean; exif: ExifData;
  exifIfdRel: number | null; gpsIfdRel: number | null;
}
function readUint16(dv: DataView, offset: number, littleEndian: boolean): number | null {
  if (offset + 2 > dv.byteLength) return null;
  return dv.getUint16(offset, littleEndian);
}
function readUint32(dv: DataView, offset: number, littleEndian: boolean): number | null {
  if (offset + 4 > dv.byteLength) return null;
  return dv.getUint32(offset, littleEndian);
}
function readRational(dv: DataView, offset: number, littleEndian: boolean): ExifRational | null {
  const num = readUint32(dv, offset, littleEndian);
  const den = readUint32(dv, offset + 4, littleEndian);
  if (num == null || den == null || den === 0) return null;
  return { num, den };
}
function readTagValueOffset(
  dv: DataView,
  base: number,
  entryOffset: number,
  littleEndian: boolean,
  type: number,
  count: number
): number | null {
  const typeSize = EXIF_TYPE_SIZE[type];
  if (!typeSize) return null;
  const valueBytes = typeSize * count;
  const valueOrOffset = readUint32(dv, entryOffset + 8, littleEndian);
  if (valueOrOffset == null) return null;
  if (valueBytes <= 4) return entryOffset + 8;
  return base + valueOrOffset;
}
function createRawTagPreview(
  dv: DataView,
  valueOffset: number,
  type: number,
  valueCount: number,
  littleEndian: boolean
): string {
  const maxAscii = 64;
  const maxNumeric = 8;
  if (type === 2) {
    const str = readAsciiString(dv, valueOffset, Math.min(valueCount, maxAscii));
    if (!str) return "";
    return valueCount > maxAscii ? `${str}...` : str;
  }
  if (type === 3 || type === 4) {
    const values: number[] = [];
    const step = type === 3 ? 2 : 4;
    const maxCount = Math.min(valueCount, maxNumeric);
    for (let i = 0; i < maxCount; i += 1) {
      const off = valueOffset + i * step;
      const v =
        type === 3 ? readUint16(dv, off, littleEndian) : readUint32(dv, off, littleEndian);
      if (v == null) break;
      values.push(v);
    }
    const preview = values.join(", ");
    return valueCount > maxNumeric ? `${preview}, ...` : preview;
  }
  if (type === 5) {
    const values: string[] = [];
    const maxCount = Math.min(valueCount, 4);
    for (let i = 0; i < maxCount; i += 1) {
      const off = valueOffset + i * 8;
      const r = readRational(dv, off, littleEndian);
      if (!r) break;
      values.push(`${r.num}/${r.den}`);
    }
    const preview = values.join(", ");
    return valueCount > 4 ? `${preview}, ...` : preview;
  }
  return "(binary/unsupported type)";
}
function recordRawTag(
  exif: ExifData,
  dv: DataView,
  littleEndian: boolean,
  ifdName: string,
  tag: number,
  type: number,
  valueCount: number,
  valueOffset: number
): void {
  const preview = createRawTagPreview(dv, valueOffset, type, valueCount, littleEndian);
  const rawTag: ExifRawTag = {
    ifd: ifdName,
    tag,
    type,
    count: valueCount,
    preview
  };
  exif.rawTags.push(rawTag);
}
export function parseExifFromApp1(dv: DataView, tiffOffset: number): ExifData | null {
  if (tiffOffset + 8 > dv.byteLength) return null;
  const endianMark = readUint16(dv, tiffOffset, false);
  const littleEndian = endianMark === 0x4949;
  if (!littleEndian && endianMark !== 0x4d4d) return null;
  const magic = readUint16(dv, tiffOffset + 2, littleEndian);
  if (magic !== 0x002a) return null;
  const ifd0Rel = readUint32(dv, tiffOffset + 4, littleEndian);
  if (ifd0Rel == null) return null;
  const ifd0 = tiffOffset + ifd0Rel;
  if (ifd0 + 2 > dv.byteLength) return null;
  const state: ExifParsingState = {
    dv,
    tiffOffset,
    littleEndian,
    exif: createEmptyExifData(),
    exifIfdRel: null,
    gpsIfdRel: null
  };
  parseIfd(state, ifd0, "IFD0", true);
  parseReferencedExifIfd(state);
  parseReferencedGpsIfd(state);
  return state.exif;
}
function createEmptyExifData(): ExifData {
  return {
    orientation: null,
    make: null,
    model: null,
    dateTimeOriginal: null,
    iso: null,
    exposureTime: null,
    fNumber: null,
    focalLength: null,
    flash: null,
    pixelXDimension: null,
    pixelYDimension: null,
    gps: null,
    rawTags: []
  };
}
function parseIfd(state: ExifParsingState, ifdStart: number, ifdName: string, isRoot: boolean): void {
  if (ifdStart + 2 > state.dv.byteLength) return;
  const count = readUint16(state.dv, ifdStart, state.littleEndian);
  if (count == null) return;
  let entryOffset = ifdStart + 2;
  for (let i = 0; i < count; i += 1) {
    if (entryOffset + 12 > state.dv.byteLength) break;
    entryOffset = parseIfdEntry(state, ifdName, entryOffset, isRoot);
  }
}
function parseIfdEntry(
  state: ExifParsingState,
  ifdName: string,
  entryOffset: number,
  isRoot: boolean
): number {
  const tag = readUint16(state.dv, entryOffset, state.littleEndian);
  const type = readUint16(state.dv, entryOffset + 2, state.littleEndian);
  const valueCount = readUint32(state.dv, entryOffset + 4, state.littleEndian);
  if (tag == null || type == null || valueCount == null) return state.dv.byteLength;
  const valueOffset = readTagValueOffset(state.dv, state.tiffOffset, entryOffset, state.littleEndian, type, valueCount);
  if (valueOffset == null || valueOffset > state.dv.byteLength) return entryOffset + 12;
  if (isRoot) readRootTag(state, tag, type, valueCount, valueOffset, entryOffset);
  else readExifTag(state, tag, type, valueCount, valueOffset);
  recordRawTag(state.exif, state.dv, state.littleEndian, ifdName, tag, type, valueCount, valueOffset);
  return entryOffset + 12;
}
function readRootTag(
  state: ExifParsingState,
  tag: number,
  type: number,
  valueCount: number,
  valueOffset: number,
  entryOffset: number
): void {
  if (tag === 0x0112 && type === 3 && valueCount >= 1) {
    state.exif.orientation = readUint16(state.dv, valueOffset, state.littleEndian);
  } else if ((tag === 0x010f || tag === 0x0110) && type === 2) {
    readCameraString(state, tag, valueOffset, valueCount);
  } else if (tag === 0x8769 && (type === 4 || type === 3) && valueCount === 1) {
    state.exifIfdRel = readUint32(state.dv, entryOffset + 8, state.littleEndian);
  } else if (tag === 0x8825 && (type === 4 || type === 3) && valueCount === 1) {
    state.gpsIfdRel = readUint32(state.dv, entryOffset + 8, state.littleEndian);
  }
}
function readCameraString(state: ExifParsingState, tag: number, valueOffset: number, valueCount: number): void {
  const str = readAsciiString(state.dv, valueOffset, valueCount);
  if (!str) return;
  if (tag === 0x010f) state.exif.make = str;
  if (tag === 0x0110) state.exif.model = str;
}
function readExifTag(
  state: ExifParsingState,
  tag: number,
  type: number,
  valueCount: number,
  valueOffset: number
): void {
  if (tag === 0x8827 && (type === 3 || type === 4) && valueCount >= 1) {
    state.exif.iso = readShortOrLong(state, type, valueOffset);
  } else if (tag === 0x829a && type === 5 && valueCount >= 1) {
    state.exif.exposureTime = readRational(state.dv, valueOffset, state.littleEndian);
  } else if (tag === 0x829d && type === 5 && valueCount >= 1) {
    state.exif.fNumber = readRational(state.dv, valueOffset, state.littleEndian);
  } else if (tag === 0x920a && type === 5 && valueCount >= 1) {
    state.exif.focalLength = readRational(state.dv, valueOffset, state.littleEndian);
  } else {
    readSecondaryExifTag(state, tag, type, valueCount, valueOffset);
  }
}
function readSecondaryExifTag(
  state: ExifParsingState,
  tag: number,
  type: number,
  valueCount: number,
  valueOffset: number
): void {
  if (tag === 0x9003 && type === 2) {
    const str = readAsciiString(state.dv, valueOffset, valueCount);
    if (str) state.exif.dateTimeOriginal = str;
  } else if (tag === 0x9209 && type === 3 && valueCount >= 1) {
    state.exif.flash = readUint16(state.dv, valueOffset, state.littleEndian);
  } else if (tag === 0xa002 && (type === 3 || type === 4) && valueCount >= 1) {
    state.exif.pixelXDimension = readShortOrLong(state, type, valueOffset);
  } else if (tag === 0xa003 && (type === 3 || type === 4) && valueCount >= 1) {
    state.exif.pixelYDimension = readShortOrLong(state, type, valueOffset);
  }
}
function readShortOrLong(state: ExifParsingState, type: number, valueOffset: number): number | null {
  return type === 3
    ? readUint16(state.dv, valueOffset, state.littleEndian)
    : readUint32(state.dv, valueOffset, state.littleEndian);
}
function parseReferencedExifIfd(state: ExifParsingState): void {
  if (state.exifIfdRel == null) return;
  const exifIfd = state.tiffOffset + state.exifIfdRel;
  if (exifIfd + 2 <= state.dv.byteLength) parseIfd(state, exifIfd, "ExifIFD", false);
}
function parseReferencedGpsIfd(state: ExifParsingState): void {
  if (state.gpsIfdRel == null) return;
  const gpsIfd = state.tiffOffset + state.gpsIfdRel;
  if (gpsIfd + 2 > state.dv.byteLength) return;
  const gps: ExifGps = { latRef: null, lat: null, lonRef: null, lon: null };
  parseGpsIfdEntries(state, gpsIfd, gps);
  if (gps.lat && gps.lon && gps.latRef && gps.lonRef) state.exif.gps = gps;
}
function parseGpsIfdEntries(state: ExifParsingState, gpsIfd: number, gps: ExifGps): void {
  const count = readUint16(state.dv, gpsIfd, state.littleEndian);
  if (count == null) return;
  let entryOffset = gpsIfd + 2;
  for (let i = 0; i < count; i += 1) {
    if (entryOffset + 12 > state.dv.byteLength) break;
    entryOffset = parseGpsEntry(state, gps, entryOffset);
  }
}
function parseGpsEntry(state: ExifParsingState, gps: ExifGps, entryOffset: number): number {
  const tag = readUint16(state.dv, entryOffset, state.littleEndian);
  const type = readUint16(state.dv, entryOffset + 2, state.littleEndian);
  const valueCount = readUint32(state.dv, entryOffset + 4, state.littleEndian);
  if (tag == null || type == null || valueCount == null) return state.dv.byteLength;
  const valueOffset = readTagValueOffset(state.dv, state.tiffOffset, entryOffset, state.littleEndian, type, valueCount);
  if (valueOffset == null || valueOffset > state.dv.byteLength) return entryOffset + 12;
  recordRawTag(state.exif, state.dv, state.littleEndian, "GPSIFD", tag, type, valueCount, valueOffset);
  readGpsTag(state, gps, tag, type, valueCount, valueOffset);
  return entryOffset + 12;
}
function readGpsTag(
  state: ExifParsingState,
  gps: ExifGps,
  tag: number,
  type: number,
  valueCount: number,
  valueOffset: number
): void {
  if (tag === 0x0001 && type === 2 && valueCount >= 1) {
    gps.latRef = readAsciiString(state.dv, valueOffset, valueCount).trim();
  } else if (tag === 0x0002 && type === 5 && valueCount >= 3) {
    gps.lat = readGpsCoordinate(state, valueOffset);
  } else if (tag === 0x0003 && type === 2 && valueCount >= 1) {
    gps.lonRef = readAsciiString(state.dv, valueOffset, valueCount).trim();
  } else if (tag === 0x0004 && type === 5 && valueCount >= 3) {
    gps.lon = readGpsCoordinate(state, valueOffset);
  }
}
function readGpsCoordinate(
  state: ExifParsingState,
  valueOffset: number
): [ExifRational, ExifRational, ExifRational] | null {
  const r0 = readRational(state.dv, valueOffset, state.littleEndian);
  const r1 = readRational(state.dv, valueOffset + 8, state.littleEndian);
  const r2 = readRational(state.dv, valueOffset + 16, state.littleEndian);
  return r0 && r1 && r2 ? [r0, r1, r2] : null;
}
