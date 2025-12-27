"use strict";

import { MockFile } from "../helpers/mock-file.js";

const asciiBytes = (text: string, length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = index < text.length ? text.charCodeAt(index) & 0xff : 0x20;
  }
  if (length > 0) bytes[Math.min(text.length, length - 1)] = 0x00;
  return bytes;
};

export const createTgaV2WithExtensionAndDeveloperArea = () => {
  const idText = "hello";
  const idLength = idText.length;
  const imageDataBytes = 3;
  const extensionOffset = 18 + idLength + imageDataBytes;
  const developerOffset = extensionOffset + 495;
  const devDirSize = 2 + 10;
  const tagDataOffset = developerOffset + devDirSize;
  const tagData = new Uint8Array([0x54, 0x41, 0x47, 0x44, 0x41, 0x54, 0x41, 0x21]); // "TAGDATA!"
  const footerOffset = tagDataOffset + tagData.length;
  const fileSize = footerOffset + 26;

  const bytes = new Uint8Array(fileSize);
  const dv = new DataView(bytes.buffer);

  bytes[0] = idLength;
  bytes[1] = 0;
  bytes[2] = 2;
  dv.setUint16(12, 1, true);
  dv.setUint16(14, 1, true);
  bytes[16] = 24;
  bytes[17] = 0;

  bytes.set(Buffer.from(idText, "ascii"), 18);
  bytes[18 + idLength + 0] = 0x00;
  bytes[18 + idLength + 1] = 0x00;
  bytes[18 + idLength + 2] = 0xff;

  dv.setUint16(extensionOffset + 0, 495, true);
  bytes.set(asciiBytes("Unit Test", 41), extensionOffset + 2);
  bytes.set(asciiBytes("Hello from extension area", 324), extensionOffset + 43);
  dv.setUint16(extensionOffset + 367, 12, true);
  dv.setUint16(extensionOffset + 369, 31, true);
  dv.setUint16(extensionOffset + 371, 2025, true);
  dv.setUint16(extensionOffset + 373, 23, true);
  dv.setUint16(extensionOffset + 375, 59, true);
  dv.setUint16(extensionOffset + 377, 58, true);
  bytes.set(asciiBytes("Job-42", 41), extensionOffset + 379);
  dv.setUint16(extensionOffset + 420, 1, true);
  dv.setUint16(extensionOffset + 422, 2, true);
  dv.setUint16(extensionOffset + 424, 3, true);
  bytes.set(asciiBytes("Binary101", 41), extensionOffset + 426);
  dv.setUint16(extensionOffset + 467, 101, true);
  bytes[extensionOffset + 469] = 0x61;
  dv.setUint32(extensionOffset + 470, 0x11223344, true);
  dv.setUint16(extensionOffset + 474, 1, true);
  dv.setUint16(extensionOffset + 476, 1, true);
  dv.setUint16(extensionOffset + 478, 22, true);
  dv.setUint16(extensionOffset + 480, 10, true);
  dv.setUint32(extensionOffset + 482, 0, true);
  dv.setUint32(extensionOffset + 486, 0, true);
  dv.setUint32(extensionOffset + 490, 0, true);
  bytes[extensionOffset + 494] = 0;

  dv.setUint16(developerOffset + 0, 1, true);
  dv.setUint16(developerOffset + 2, 42, true);
  dv.setUint32(developerOffset + 4, tagDataOffset, true);
  dv.setUint32(developerOffset + 8, tagData.length, true);

  bytes.set(tagData, tagDataOffset);

  dv.setUint32(footerOffset + 0, extensionOffset, true);
  dv.setUint32(footerOffset + 4, developerOffset, true);
  bytes.set(Buffer.from("TRUEVISION-XFILE", "ascii"), footerOffset + 8);
  bytes[footerOffset + 24] = 0x2e;
  bytes[footerOffset + 25] = 0x00;

  return new MockFile(bytes, "v2.tga", "image/x-tga");
};

export const createTgaColorMappedFile = () => {
  const paletteBytes = 2 * 3;
  const imageDataBytes = 1;
  const fileSize = 18 + paletteBytes + imageDataBytes;
  const bytes = new Uint8Array(fileSize);
  const dv = new DataView(bytes.buffer);

  bytes[0] = 0;
  bytes[1] = 1;
  bytes[2] = 1;
  dv.setUint16(5, 2, true);
  bytes[7] = 24;
  dv.setUint16(12, 1, true);
  dv.setUint16(14, 1, true);
  bytes[16] = 8;
  bytes[17] = 0;

  bytes.set(new Uint8Array([0x00, 0x00, 0xff, 0x00, 0xff, 0x00]), 18);
  bytes[18 + paletteBytes] = 1;

  return new MockFile(bytes, "palette.tga", "image/x-tga");
};

export const createTgaWithBinaryImageId = () => {
  const idBytes = new Uint8Array([0x00, 0xff, 0x10, 0x20]);
  const pixelBytes = 3;
  const bytes = new Uint8Array(18 + idBytes.length + pixelBytes);
  const dv = new DataView(bytes.buffer);

  bytes[0] = idBytes.length;
  bytes[1] = 0;
  bytes[2] = 2;
  dv.setUint16(12, 1, true);
  dv.setUint16(14, 1, true);
  bytes[16] = 24;
  bytes[17] = 0;

  bytes.set(idBytes, 18);
  bytes[18 + idBytes.length + 0] = 0x00;
  bytes[18 + idBytes.length + 1] = 0x00;
  bytes[18 + idBytes.length + 2] = 0xff;

  return new MockFile(bytes, "binary-id.tga", "image/x-tga");
};
