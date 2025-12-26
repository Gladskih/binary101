"use strict";

import { MockFile } from "../helpers/mock-file.js";

const fromHex = (hex: string): Uint8Array =>
  new Uint8Array(Buffer.from(hex.replace(/\s+/g, ""), "hex"));

export const createBmpFile = () =>
  new MockFile(
    fromHex(
      "424D3A0000000000000036000000" +
        "280000000100000001000000010018000000000004000000130B0000130B00000000000000000000" +
        "0000FF00"
    ),
    "sample.bmp",
    "image/bmp"
  );

export const createBmpCoreHeaderFile = () =>
  new MockFile(
    fromHex(
      "424D1E000000000000001A000000" +
        "0C0000000100010001001800" +
        "0000FF00"
    ),
    "core.bmp",
    "image/bmp"
  );

export const createBmp8BitPaletteFile = () =>
  new MockFile(
    fromHex(
      "424D4A0000000000000046000000" +
        "280000000100000001000000010008000000000004000000130B0000130B00000400000000000000" +
        "00000000FF00000000FF00000000FF00" +
        "03000000"
    ),
    "pal4.bmp",
    "image/bmp"
  );

export const createBmp16BitBitfieldsFile = () =>
  new MockFile(
    fromHex(
      "424D460000000000000042000000" +
        "280000000100000001000000010010000300000004000000130B0000130B00000000000000000000" +
        "00F80000E00700001F000000" +
        "00F80000"
    ),
    "565.bmp",
    "image/bmp"
  );

export const createTruncatedBmpFile = () =>
  new MockFile(
    fromHex("424D3A00000000000000"),
    "truncated.bmp",
    "image/bmp"
  );

export const createBmpWithPixelOffsetPastEof = () =>
  new MockFile(
    fromHex(
      "424D3A0000000000000064000000" +
        "280000000100000001000000010018000000000004000000130B0000130B00000000000000000000" +
        "0000FF00"
    ),
    "bad-offset.bmp",
    "image/bmp"
  );

