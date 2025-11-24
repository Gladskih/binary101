"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExifFromApp1 } from "../../dist/analyzers/jpeg/exif.js";

const writeEntry = (dv, offset, tag, type, count, value, littleEndian = true) => {
  dv.setUint16(offset, tag, littleEndian);
  dv.setUint16(offset + 2, type, littleEndian);
  dv.setUint32(offset + 4, count, littleEndian);
  dv.setUint32(offset + 8, value, littleEndian);
};

test("parseExifFromApp1 parses EXIF and GPS fields with raw tags", () => {
  const buffer = new ArrayBuffer(512);
  const dv = new DataView(buffer);
  const u8 = new Uint8Array(buffer);

  // TIFF header (little-endian)
  u8[0] = 0x49;
  u8[1] = 0x49;
  dv.setUint16(2, 0x002a, true);
  dv.setUint32(4, 8, true); // IFD0 offset

  // IFD0 entries
  const ifd0Count = 3;
  dv.setUint16(8, ifd0Count, true);
  const entryStart = 10;
  writeEntry(dv, entryStart + 0 * 12, 0x0112, 3, 1, 1); // orientation = 1
  writeEntry(dv, entryStart + 1 * 12, 0x8769, 4, 1, 100); // ExifIFD pointer
  writeEntry(dv, entryStart + 2 * 12, 0x8825, 4, 1, 200); // GPS IFD pointer
  dv.setUint32(entryStart + ifd0Count * 12, 0, true); // next IFD = none

  // Exif IFD
  dv.setUint16(100, 8, true);
  let dataPtr = 300;
  const writeRational = (num, den) => {
    dv.setUint32(dataPtr, num, true);
    dv.setUint32(dataPtr + 4, den, true);
    const off = dataPtr;
    dataPtr += 8;
    return off;
  };
  const dateString = "2022:08:01 10:11:12";
  const dateOffset = dataPtr;
  for (let i = 0; i < dateString.length; i += 1) {
    u8[dateOffset + i] = dateString.charCodeAt(i);
  }
  dataPtr += dateString.length + 1;
  const exposureOff = writeRational(1, 125);
  const fNumberOff = writeRational(28, 10);
  const focalOff = writeRational(85, 1);
  writeEntry(dv, 102, 0x8827, 3, 1, 200); // ISO
  writeEntry(dv, 114, 0x829a, 5, 1, exposureOff); // exposure time
  writeEntry(dv, 126, 0x829d, 5, 1, fNumberOff); // f-number
  writeEntry(dv, 138, 0x920a, 5, 1, focalOff); // focal length
  writeEntry(dv, 150, 0x9003, 2, dateString.length + 1, dateOffset); // capture time
  writeEntry(dv, 162, 0x9209, 3, 1, 1); // flash fired
  writeEntry(dv, 174, 0xa002, 3, 1, 4000); // width
  writeEntry(dv, 186, 0xa003, 3, 1, 3000); // height
  dv.setUint32(100 + 2 + 8 * 12, 0, true); // next IFD

  // GPS IFD
  dv.setUint16(200, 4, true);
  const gpsLatOffset = dataPtr;
  const gpsLonOffset = gpsLatOffset + 24;
  const writeGpsTriple = base => {
    dv.setUint32(base + 0, 37, true);
    dv.setUint32(base + 4, 1, true);
    dv.setUint32(base + 8, 47, true);
    dv.setUint32(base + 12, 1, true);
    dv.setUint32(base + 16, 3000, true);
    dv.setUint32(base + 20, 100, true);
  };
  writeGpsTriple(gpsLatOffset);
  writeGpsTriple(gpsLonOffset);
  // GPS refs stored inline in the value field.
  writeEntry(dv, 202, 0x0001, 2, 2, 0); // N
  u8[202 + 8] = "N".charCodeAt(0);
  u8[202 + 9] = 0;
  writeEntry(dv, 214, 0x0002, 5, 3, gpsLatOffset);
  writeEntry(dv, 226, 0x0003, 2, 2, 0); // E
  u8[226 + 8] = "E".charCodeAt(0);
  u8[226 + 9] = 0;
  writeEntry(dv, 238, 0x0004, 5, 3, gpsLonOffset);
  dv.setUint32(200 + 2 + 4 * 12, 0, true);

  const exif = parseExifFromApp1(new DataView(buffer), 0);
  assert.ok(exif);
  assert.equal(exif.orientation, 1);
  assert.equal(exif.iso, 200);
  assert.equal(exif.exposureTime.num, 1);
  assert.equal(exif.fNumber.num, 28);
  assert.equal(exif.focalLength.num, 85);
  assert.equal(exif.dateTimeOriginal, dateString);
  assert.equal(exif.flash, 1);
  assert.equal(exif.pixelXDimension, 4000);
  assert.equal(exif.pixelYDimension, 3000);
  assert.ok(exif.gps);
  assert.equal(exif.gps.latRef, "N");
  assert.equal(exif.gps.lonRef, "E");
  assert.ok(Array.isArray(exif.rawTags));
  assert.ok(exif.rawTags.length >= 10);
});

test("parseExifFromApp1 returns null for invalid headers", () => {
  const dv = new DataView(new ArrayBuffer(4));
  assert.equal(parseExifFromApp1(dv, 0), null);
});
