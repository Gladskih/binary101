"use strict";

import { MockFile } from "../helpers/mock-file.js";

const concatParts = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const part of parts) {
    out.set(part, cursor);
    cursor += part.length;
  }
  return out;
};

const u16be = (value: number): Uint8Array => {
  const out = new Uint8Array(2);
  out[0] = (value >> 8) & 0xff;
  out[1] = value & 0xff;
  return out;
};

const encodePts = (pts90k: number): Uint8Array => {
  const value = pts90k >>> 0;
  const out = new Uint8Array(5);
  out[0] = (0x2 << 4) | (((value >>> 30) & 0x07) << 1) | 0x01;
  out[1] = (value >>> 22) & 0xff;
  out[2] = (((value >>> 15) & 0x7f) << 1) | 0x01;
  out[3] = (value >>> 7) & 0xff;
  out[4] = ((value & 0x7f) << 1) | 0x01;
  return out;
};

const createMpeg2PackHeader = (opts: {
  scrBase90k: number;
  scrExt: number;
  muxRate: number;
  stuffingLength: number;
}): Uint8Array => {
  const scrBase = opts.scrBase90k >>> 0;
  const scrExt = opts.scrExt & 0x1ff;
  const muxRate = opts.muxRate & 0x3fffff;
  const stuffingLength = opts.stuffingLength & 0x07;

  const scrPart1 = (scrBase >>> 15) & 0x7fff;
  const scrPart2 = scrBase & 0x7fff;

  const header = new Uint8Array(14 + stuffingLength);
  header.set(new Uint8Array([0x00, 0x00, 0x01, 0xba]), 0);

  header[4] = 0x40 | (((scrBase >>> 30) & 0x07) << 3) | 0x04 | ((scrPart1 >>> 13) & 0x03);
  header[5] = (scrPart1 >>> 5) & 0xff;
  header[6] = ((scrPart1 & 0x1f) << 3) | 0x04 | ((scrPart2 >>> 13) & 0x03);
  header[7] = (scrPart2 >>> 5) & 0xff;
  header[8] = ((scrPart2 & 0x1f) << 3) | 0x04 | ((scrExt >>> 7) & 0x03);
  header[9] = ((scrExt & 0x7f) << 1) | 0x01;

  header[10] = (muxRate >>> 14) & 0xff;
  header[11] = (muxRate >>> 6) & 0xff;
  header[12] = ((muxRate & 0x3f) << 2) | 0x03;
  header[13] = 0xf8 | stuffingLength;

  if (stuffingLength) {
    header.fill(0xff, 14);
  }
  return header;
};

const createSystemHeader = (): Uint8Array => {
  const payload = new Uint8Array([
    0x80, 0xc4, 0xe1, 0x04, 0xe1, 0xff, 0xe0, 0xe0, 0xe8, 0xc0, 0xc0, 0x20
  ]);
  return concatParts([new Uint8Array([0x00, 0x00, 0x01, 0xbb]), u16be(payload.length), payload]);
};

const createPesPacket = (streamId: number, pts90k: number, payload: Uint8Array): Uint8Array => {
  const pts = encodePts(pts90k);
  const header = concatParts([new Uint8Array([0x80, 0x80, 0x05]), pts]);
  const pesLength = header.length + payload.length;
  const packetHeader = concatParts([new Uint8Array([0x00, 0x00, 0x01, streamId]), u16be(pesLength)]);
  return concatParts([packetHeader, header, payload]);
};

export const createMpegPsFile = (): MockFile => {
  const pack1 = createMpeg2PackHeader({ scrBase90k: 0, scrExt: 0, muxRate: 25200, stuffingLength: 0 });
  const system = createSystemHeader();
  const videoPayload = new Uint8Array([0x00, 0x00, 0x01, 0xb3, 0x11, 0x22]);
  const video0 = createPesPacket(0xe0, 0, videoPayload);
  const pack2 = createMpeg2PackHeader({ scrBase90k: 90000, scrExt: 0, muxRate: 25200, stuffingLength: 0 });
  const video1 = createPesPacket(0xe0, 90000, videoPayload);
  const audio0 = createPesPacket(0xc0, 0, new Uint8Array([0x00]));
  const endCode = new Uint8Array([0x00, 0x00, 0x01, 0xb9]);

  const bytes = concatParts([pack1, system, video0, pack2, video1, audio0, endCode]);
  return new MockFile(bytes, "sample.mpg", "video/mpeg");
};

