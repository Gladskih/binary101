"use strict";

import { MockFile } from "../helpers/mock-file.js";

const buildJpeg = segments => {
  const bytes = [];
  // SOI
  bytes.push(0xff, 0xd8);
  segments.forEach(seg => bytes.push(...seg));
  return new MockFile(new Uint8Array(bytes), "sample.jpg", "image/jpeg");
};

const segment = (marker, payload) => {
  const len = payload.length + 2;
  return [0xff, marker, (len >> 8) & 0xff, len & 0xff, ...payload];
};

export const createJpegWithBrokenExif = () => {
  // APP1 with EXIF marker but truncated payload
  const app1 = segment(0xe1, [0x45, 0x78, 0x69, 0x66, 0x00, 0x00, 0x01]);
  const eoi = [0xff, 0xd9];
  return buildJpeg([app1, eoi]);
};

export const createJpegNoSof = () => {
  // JPEG with only comment and no SOF marker
  const com = segment(0xfe, [0x00, 0x01]);
  const eoi = [0xff, 0xd9];
  return buildJpeg([com, eoi]);
};
