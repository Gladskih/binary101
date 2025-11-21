"use strict";

import { MockFile } from "../helpers/mock-file.mjs";

// Minimal EOCD only, central directory offset points outside file
export const createZipWithBadCdOffset = () =>
  new MockFile(
    new Uint8Array([
      0x50, 0x4b, 0x05, 0x06, // EOCD signature
      0x00, 0x00, 0x00, 0x00, // disk numbers
      0x01, 0x00, 0x01, 0x00, // entries this/total
      0xff, 0xff, 0xff, 0xff, // central dir size (invalid)
      0xff, 0xff, 0xff, 0xff, // central dir offset (invalid)
      0x00, 0x00 // comment length
    ]),
    "bad-cd.zip",
    "application/zip"
  );

// ZIP64 locator present but missing referenced EOCD
export const createZipWithMissingZip64 = () =>
  new MockFile(
    new Uint8Array([
      0x50, 0x4b, 0x06, 0x07, // ZIP64 EOCD locator signature
      0x00, 0x00, 0x00, 0x00, // disk with EOCD
      0x10, 0x00, 0x00, 0x00, // offset to ZIP64 EOCD (points beyond file)
      0x01, 0x00, 0x00, 0x00, // total disks
      0x50, 0x4b, 0x05, 0x06, // EOCD signature
      0x00, 0x00, 0x00, 0x00, // disk numbers
      0x00, 0x00, 0x00, 0x00, // entries this/total
      0x00, 0x00, 0x00, 0x00, // central dir size/offset
      0x00, 0x00 // comment length
    ]),
    "missing-zip64.zip",
    "application/zip"
  );
