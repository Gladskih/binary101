"use strict";

import { MockFile } from "../helpers/mock-file.mjs";

const buildId3v2Header = size => {
  const bytes = new Uint8Array(10).fill(0);
  bytes.set([0x49, 0x44, 0x33]); // ID3
  bytes[3] = 3; // version 2.3
  // syncsafe size
  const sz = size;
  bytes[6] = (sz >> 21) & 0x7f;
  bytes[7] = (sz >> 14) & 0x7f;
  bytes[8] = (sz >> 7) & 0x7f;
  bytes[9] = sz & 0x7f;
  return bytes;
};

export const createMp3WithOnlyId3v2 = () => {
  const id3 = buildId3v2Header(20);
  const payload = new Uint8Array(id3.length + 20).fill(0);
  payload.set(id3, 0);
  return new MockFile(payload, "id3-only.mp3", "audio/mpeg");
};

export const createMp3WithGarbageFrame = () => {
  // invalid frame sync
  const bytes = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0xff, 0xfa, 0x90, 0x64]);
  return new MockFile(bytes, "garbage.mp3", "audio/mpeg");
};
