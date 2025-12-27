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

export const createBmpOs2InfoHeader2File = () => {
  const dibSize = 64;
  const headerStart = 14;
  const pixelOffset = headerStart + dibSize;
  const pixelBytes = 4;
  const fileSize = pixelOffset + pixelBytes;
  const bytes = new Uint8Array(fileSize);
  const dv = new DataView(bytes.buffer);

  bytes[0] = 0x42;
  bytes[1] = 0x4d;
  dv.setUint32(2, fileSize, true);
  dv.setUint32(10, pixelOffset, true);

  dv.setUint32(headerStart + 0, dibSize, true);
  dv.setInt32(headerStart + 4, 1, true);
  dv.setInt32(headerStart + 8, 1, true);
  dv.setUint16(headerStart + 12, 1, true);
  dv.setUint16(headerStart + 14, 24, true);
  dv.setUint32(headerStart + 16, 0, true);
  dv.setUint32(headerStart + 20, pixelBytes, true);
  dv.setInt32(headerStart + 24, 2835, true);
  dv.setInt32(headerStart + 28, 2835, true);
  dv.setUint32(headerStart + 32, 0, true);
  dv.setUint32(headerStart + 36, 0, true);

  dv.setUint32(headerStart + 40, 0x11223344, true);
  dv.setUint32(headerStart + 44, 0x55667788, true);
  dv.setUint32(headerStart + 48, 0x99aabbcc, true);
  dv.setUint32(headerStart + 52, 0xddeeff00, true);

  bytes[pixelOffset + 0] = 0x00;
  bytes[pixelOffset + 1] = 0x00;
  bytes[pixelOffset + 2] = 0xff;
  bytes[pixelOffset + 3] = 0x00;

  return new MockFile(bytes, "os2-infoheader2.bmp", "image/bmp");
};

export const createBmpV5SrgbFile = () => {
  const dibSize = 124;
  const pixelOffset = 14 + dibSize;
  const pixelBytes = 4;
  const fileSize = pixelOffset + pixelBytes;
  const bytes = new Uint8Array(fileSize);
  const dv = new DataView(bytes.buffer);

  bytes[0] = 0x42;
  bytes[1] = 0x4d;
  dv.setUint32(2, fileSize, true);
  dv.setUint16(6, 0, true);
  dv.setUint16(8, 0, true);
  dv.setUint32(10, pixelOffset, true);

  const headerStart = 14;
  dv.setUint32(headerStart + 0, dibSize, true);
  dv.setInt32(headerStart + 4, 1, true);
  dv.setInt32(headerStart + 8, 1, true);
  dv.setUint16(headerStart + 12, 1, true);
  dv.setUint16(headerStart + 14, 32, true);
  dv.setUint32(headerStart + 16, 0, true);
  dv.setUint32(headerStart + 20, pixelBytes, true);
  dv.setInt32(headerStart + 24, 2835, true);
  dv.setInt32(headerStart + 28, 2835, true);
  dv.setUint32(headerStart + 56, 0x73524742, true);
  dv.setUint32(headerStart + 108, 4, true);

  bytes[pixelOffset + 0] = 0x00;
  bytes[pixelOffset + 1] = 0x00;
  bytes[pixelOffset + 2] = 0xff;
  bytes[pixelOffset + 3] = 0x00;

  return new MockFile(bytes, "v5-srgb.bmp", "image/bmp");
};

export const createBmpV5LinkedProfileFile = () => {
  const dibSize = 124;
  const headerStart = 14;
  const paddingBytes = 2;
  const pixelOffset = headerStart + dibSize + paddingBytes;
  const pixelBytes = 4;
  const profileName = Buffer.from("sRGB.icc\u0000", "latin1");
  const profileOffsetFromHeader = pixelOffset + pixelBytes - headerStart;
  const fileSize = pixelOffset + pixelBytes + profileName.length;
  const bytes = new Uint8Array(fileSize);
  const dv = new DataView(bytes.buffer);

  bytes[0] = 0x42;
  bytes[1] = 0x4d;
  dv.setUint32(2, fileSize, true);
  dv.setUint32(10, pixelOffset, true);

  dv.setUint32(headerStart + 0, dibSize, true);
  dv.setInt32(headerStart + 4, 1, true);
  dv.setInt32(headerStart + 8, 1, true);
  dv.setUint16(headerStart + 12, 1, true);
  dv.setUint16(headerStart + 14, 32, true);
  dv.setUint32(headerStart + 16, 0, true);
  dv.setUint32(headerStart + 20, pixelBytes, true);
  dv.setUint32(headerStart + 56, 0x4c494e4b, true);
  dv.setUint32(headerStart + 108, 4, true);
  dv.setUint32(headerStart + 112, profileOffsetFromHeader, true);
  dv.setUint32(headerStart + 116, profileName.length, true);

  bytes[pixelOffset + 0] = 0x00;
  bytes[pixelOffset + 1] = 0x00;
  bytes[pixelOffset + 2] = 0xff;
  bytes[pixelOffset + 3] = 0x00;
  bytes.set(profileName, pixelOffset + pixelBytes);

  return new MockFile(bytes, "v5-linked-profile.bmp", "image/bmp");
};

export const createBmpV5EmbeddedProfileFile = () => {
  const dibSize = 124;
  const headerStart = 14;
  const paddingBytes = 2;
  const pixelOffset = headerStart + dibSize + paddingBytes;
  const pixelBytes = 4;
  const profileData = new Uint8Array(64);
  profileData.set(Buffer.from("acsp", "ascii"), 36);
  const profileOffsetFromHeader = pixelOffset + pixelBytes - headerStart;
  const fileSize = pixelOffset + pixelBytes + profileData.length;
  const bytes = new Uint8Array(fileSize);
  const dv = new DataView(bytes.buffer);

  bytes[0] = 0x42;
  bytes[1] = 0x4d;
  dv.setUint32(2, fileSize, true);
  dv.setUint32(10, pixelOffset, true);

  dv.setUint32(headerStart + 0, dibSize, true);
  dv.setInt32(headerStart + 4, 1, true);
  dv.setInt32(headerStart + 8, 1, true);
  dv.setUint16(headerStart + 12, 1, true);
  dv.setUint16(headerStart + 14, 32, true);
  dv.setUint32(headerStart + 16, 0, true);
  dv.setUint32(headerStart + 20, pixelBytes, true);
  dv.setUint32(headerStart + 56, 0x4d424544, true);
  dv.setUint32(headerStart + 108, 4, true);
  dv.setUint32(headerStart + 112, profileOffsetFromHeader, true);
  dv.setUint32(headerStart + 116, profileData.length, true);

  bytes[pixelOffset + 0] = 0x00;
  bytes[pixelOffset + 1] = 0x00;
  bytes[pixelOffset + 2] = 0xff;
  bytes[pixelOffset + 3] = 0x00;
  bytes.set(profileData, pixelOffset + pixelBytes);

  return new MockFile(bytes, "v5-embedded-profile.bmp", "image/bmp");
};
