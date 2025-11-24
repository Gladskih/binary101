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
  if (valueBytes <= 4) {
    return entryOffset + 8;
  }
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

  const exif: ExifData = {
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

  let exifIfdRel: number | null = null;
  let gpsIfdRel: number | null = null;

  const parseIfd = (ifdStart: number, ifdName: string, isRoot: boolean): void => {
    if (ifdStart + 2 > dv.byteLength) return;
    const count = readUint16(dv, ifdStart, littleEndian);
    if (count == null) return;
    let entryOffset = ifdStart + 2;
    for (let i = 0; i < count; i += 1) {
      if (entryOffset + 12 > dv.byteLength) break;
      const tag = readUint16(dv, entryOffset, littleEndian);
      const type = readUint16(dv, entryOffset + 2, littleEndian);
      const valueCount = readUint32(dv, entryOffset + 4, littleEndian);
      if (tag == null || type == null || valueCount == null) break;
      const valueOffset = readTagValueOffset(
        dv,
        tiffOffset,
        entryOffset,
        littleEndian,
        type,
        valueCount
      );
      if (valueOffset == null || valueOffset > dv.byteLength) {
        entryOffset += 12;
        continue;
      }

      if (isRoot) {
        if (tag === 0x0112 && type === 3 && valueCount >= 1) {
          const v = readUint16(dv, valueOffset, littleEndian);
          if (v != null) exif.orientation = v;
        } else if ((tag === 0x010f || tag === 0x0110) && type === 2) {
          const str = readAsciiString(dv, valueOffset, valueCount);
          if (str) {
            if (tag === 0x010f) exif.make = str;
            if (tag === 0x0110) exif.model = str;
          }
        } else if (tag === 0x8769 && (type === 4 || type === 3) && valueCount === 1) {
          exifIfdRel = readUint32(dv, entryOffset + 8, littleEndian);
        } else if (tag === 0x8825 && (type === 4 || type === 3) && valueCount === 1) {
          gpsIfdRel = readUint32(dv, entryOffset + 8, littleEndian);
        }
      } else {
        if (tag === 0x8827 && (type === 3 || type === 4) && valueCount >= 1) {
          const v =
            type === 3
              ? readUint16(dv, valueOffset, littleEndian)
              : readUint32(dv, valueOffset, littleEndian);
          if (v != null) exif.iso = v;
        } else if (tag === 0x829a && type === 5 && valueCount >= 1) {
          const r = readRational(dv, valueOffset, littleEndian);
          if (r) exif.exposureTime = r;
        } else if (tag === 0x829d && type === 5 && valueCount >= 1) {
          const r = readRational(dv, valueOffset, littleEndian);
          if (r) exif.fNumber = r;
        } else if (tag === 0x920a && type === 5 && valueCount >= 1) {
          const r = readRational(dv, valueOffset, littleEndian);
          if (r) exif.focalLength = r;
        } else if (tag === 0x9003 && type === 2) {
          const str = readAsciiString(dv, valueOffset, valueCount);
          if (str) exif.dateTimeOriginal = str;
        } else if (tag === 0x9209 && type === 3 && valueCount >= 1) {
          const v = readUint16(dv, valueOffset, littleEndian);
          if (v != null) exif.flash = v;
        } else if (tag === 0xa002 && (type === 3 || type === 4) && valueCount >= 1) {
          const v =
            type === 3
              ? readUint16(dv, valueOffset, littleEndian)
              : readUint32(dv, valueOffset, littleEndian);
          if (v != null) exif.pixelXDimension = v;
        } else if (tag === 0xa003 && (type === 3 || type === 4) && valueCount >= 1) {
          const v =
            type === 3
              ? readUint16(dv, valueOffset, littleEndian)
              : readUint32(dv, valueOffset, littleEndian);
          if (v != null) exif.pixelYDimension = v;
        }
      }

      recordRawTag(exif, dv, littleEndian, ifdName, tag, type, valueCount, valueOffset);

      entryOffset += 12;
    }
  };

  parseIfd(ifd0, "IFD0", true);

  if (exifIfdRel != null) {
    const exifIfd = tiffOffset + exifIfdRel;
    if (exifIfd + 2 <= dv.byteLength) {
      parseIfd(exifIfd, "ExifIFD", false);
    }
  }

  if (gpsIfdRel != null) {
    const gpsIfd = tiffOffset + gpsIfdRel;
    if (gpsIfd + 2 <= dv.byteLength) {
      const gps: ExifGps = {
        latRef: null,
        lat: null,
        lonRef: null,
        lon: null
      };
      const count = readUint16(dv, gpsIfd, littleEndian);
      if (count != null) {
        let entryOffset = gpsIfd + 2;
        for (let i = 0; i < count; i += 1) {
          if (entryOffset + 12 > dv.byteLength) break;
          const tag = readUint16(dv, entryOffset, littleEndian);
          const type = readUint16(dv, entryOffset + 2, littleEndian);
          const valueCount = readUint32(dv, entryOffset + 4, littleEndian);
          if (tag == null || type == null || valueCount == null) break;
          const valueOffset = readTagValueOffset(
            dv,
            tiffOffset,
            entryOffset,
            littleEndian,
            type,
            valueCount
          );
          if (valueOffset == null || valueOffset > dv.byteLength) {
            entryOffset += 12;
            continue;
          }

          recordRawTag(exif, dv, littleEndian, "GPSIFD", tag, type, valueCount, valueOffset);

          if (tag === 0x0001 && type === 2 && valueCount >= 1) {
            gps.latRef = readAsciiString(dv, valueOffset, valueCount).trim();
          } else if (tag === 0x0002 && type === 5 && valueCount >= 3) {
            const r0 = readRational(dv, valueOffset + 0, littleEndian);
            const r1 = readRational(dv, valueOffset + 8, littleEndian);
            const r2 = readRational(dv, valueOffset + 16, littleEndian);
            if (r0 && r1 && r2) gps.lat = [r0, r1, r2];
          } else if (tag === 0x0003 && type === 2 && valueCount >= 1) {
            gps.lonRef = readAsciiString(dv, valueOffset, valueCount).trim();
          } else if (tag === 0x0004 && type === 5 && valueCount >= 3) {
            const r0 = readRational(dv, valueOffset + 0, littleEndian);
            const r1 = readRational(dv, valueOffset + 8, littleEndian);
            const r2 = readRational(dv, valueOffset + 16, littleEndian);
            if (r0 && r1 && r2) gps.lon = [r0, r1, r2];
          }

          entryOffset += 12;
        }
      }
      if (gps.lat && gps.lon && gps.latRef && gps.lonRef) {
        exif.gps = gps;
      }
    }
  }

  return exif;
}
