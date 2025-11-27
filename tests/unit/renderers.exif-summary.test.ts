"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderJpegExifSummary } from "../../renderers/jpeg/exif-summary.js";
import type { ExifData, ExifRational } from "../../analyzers/jpeg/types.js";

const makeRational = (num: number, den: number): ExifRational => ({ num, den });

void test("renderJpegExifSummary formats rich EXIF data and raw tags", () => {
  const exif: ExifData = {
    make: "ACME",
    model: "CAM-42",
    orientation: 1,
    dateTimeOriginal: "2021:03:05 12:34:56",
    iso: 200,
    exposureTime: makeRational(1, 125),
    fNumber: makeRational(28, 10),
    focalLength: makeRational(85, 1),
    flash: 1,
    pixelXDimension: 4000,
    pixelYDimension: 3000,
    gps: {
      latRef: "N",
      lonRef: "W",
      lat: [makeRational(37, 1), makeRational(47, 1), makeRational(3000, 100)],
      lon: [makeRational(122, 1), makeRational(25, 1), makeRational(100, 10)]
    },
    rawTags: [
      { ifd: "0th", tag: 0x010f, type: "ASCII", count: 4, preview: "ACME" },
      { ifd: "exif", tag: 0x9003, type: "ASCII", count: 8, preview: "timestamp" },
      { ifd: "gps", tag: 0x0005, type: "SHORT", count: 1, preview: "0" },
      { ifd: "unknown", tag: 0xbeef, type: "BYTE", count: 2, preview: "??" }
    ]
  };

  const html = renderJpegExifSummary(exif);

  assert.match(html, /Camera make/);
  assert.match(html, /typical orientation/);
  assert.match(html, /fast shutter/);
  assert.match(html, /fast lens/);
  assert.match(html, /short telephoto/);
  assert.match(html, /flash fired/);
  assert.match(html, /approximate capture location/);
  assert.match(html, /Recorded pixel dimensions/);
  // Raw tags table should include known and unknown tags with previews.
  assert.match(html, /All EXIF tags/);
  assert.match(html, /0x010f/);
  assert.match(html, /0xbeef/);
  assert.match(html, /timestamp/);
});

void test("renderJpegExifSummary handles edge EXIF values", () => {
  const exif: ExifData = {
    make: "",
    model: "",
    orientation: 7,
    dateTimeOriginal: "2100:01:01 00:00:00",
    iso: 6400,
    exposureTime: makeRational(2, 1),
    fNumber: makeRational(90, 10),
    focalLength: makeRational(400, 1),
    flash: 0,
    gps: { latRef: "S", lonRef: "E", lat: [makeRational(0, 0), makeRational(1, 1)], lon: [] },
    rawTags: []
  };

  const html = renderJpegExifSummary(exif);

  assert.match(html, /requires rotation/);
  assert.match(html, /camera clock looks misconfigured/);
  assert.match(html, /very high, strong noise/);
  assert.match(html, /long exposure/);
  assert.match(html, /high f-number/);
  assert.match(html, /super-telephoto/);
  assert.match(html, /flash did not fire/);
  // No GPS or pixel dimensions should still produce a table.
  assert.match(html, /GPS/);
  assert.match(html, /Not available/);
});
