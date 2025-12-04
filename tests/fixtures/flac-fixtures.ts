"use strict";

import { MockFile } from "../helpers/mock-file.js";

const textEncoder = new TextEncoder();

const writeUint24 = (view: DataView, offset: number, value: number): void => {
  view.setUint8(offset, (value >> 16) & 0xff);
  view.setUint8(offset + 1, (value >> 8) & 0xff);
  view.setUint8(offset + 2, value & 0xff);
};

const buildStreamInfo = (
  sampleRate: number,
  channels: number,
  bitsPerSample: number,
  totalSamples: number
): Uint8Array => {
  const payload = new Uint8Array(34);
  const view = new DataView(payload.buffer);
  view.setUint16(0, 0x0400, false);
  view.setUint16(2, 0x0400, false);
  writeUint24(view, 4, 0x0100);
  writeUint24(view, 7, 0x0200);
  const channelsMinusOne = Math.max(0, channels - 1) & 0x7;
  const bitsMinusOne = Math.max(0, bitsPerSample - 1) & 0x1f;
  const totalSamplesHi = (totalSamples >>> 32) & 0x0f;
  const hi =
    ((sampleRate & 0xfffff) << 12) |
    (channelsMinusOne << 9) |
    (bitsMinusOne << 4) |
    totalSamplesHi;
  const lo = totalSamples >>> 0;
  view.setUint32(10, hi >>> 0, false);
  view.setUint32(14, lo, false);
  for (let index = 0; index < 16; index += 1) {
    payload[18 + index] = index;
  }
  return payload;
};

const buildVorbisComment = (vendor: string, comments: string[]): Uint8Array => {
  const vendorBytes = textEncoder.encode(vendor);
  const parts: number[] = [];
  const pushUint32 = (value: number): void => {
    parts.push(value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff);
  };
  pushUint32(vendorBytes.length);
  parts.push(...vendorBytes);
  pushUint32(comments.length);
  comments.forEach(comment => {
    const bytes = textEncoder.encode(comment);
    pushUint32(bytes.length);
    parts.push(...bytes);
  });
  return new Uint8Array(parts);
};

const buildSeekTable = (): Uint8Array => {
  const payload = new Uint8Array(36);
  const view = new DataView(payload.buffer);
  view.setBigUint64(0, 0n, false);
  view.setBigUint64(8, 0n, false);
  view.setUint16(16, 1024, false);
  view.setBigUint64(18, 5000n, false);
  view.setBigUint64(26, 12345n, false);
  view.setUint16(34, 512, false);
  return payload;
};

const buildPictureBlock = (): Uint8Array => {
  const mime = textEncoder.encode("image/png");
  const desc = textEncoder.encode("cover art");
  const data = new Uint8Array([1, 2, 3, 4]);
  const header = new Uint8Array(32 + mime.length + desc.length);
  const view = new DataView(header.buffer);
  let offset = 0;
  view.setUint32(offset, 3, false);
  offset += 4;
  view.setUint32(offset, mime.length, false);
  offset += 4;
  header.set(mime, offset);
  offset += mime.length;
  view.setUint32(offset, desc.length, false);
  offset += 4;
  header.set(desc, offset);
  offset += desc.length;
  view.setUint32(offset, 64, false);
  view.setUint32(offset + 4, 64, false);
  view.setUint32(offset + 8, 24, false);
  view.setUint32(offset + 12, 0, false);
  view.setUint32(offset + 16, data.length, false);
  const payload = new Uint8Array(header.length + data.length);
  payload.set(header, 0);
  payload.set(data, header.length);
  return payload;
};

const wrapBlock = (type: number, isLast: boolean, payload: Uint8Array): Uint8Array => {
  const output = new Uint8Array(4 + payload.length);
  output[0] = (isLast ? 0x80 : 0) | (type & 0x7f);
  output[1] = (payload.length >> 16) & 0xff;
  output[2] = (payload.length >> 8) & 0xff;
  output[3] = payload.length & 0xff;
  output.set(payload, 4);
  return output;
};

export const createFlacFile = (): MockFile => {
  const streamInfo = wrapBlock(0, false, buildStreamInfo(44100, 2, 16, 88200));
  const vorbis = wrapBlock(
    4,
    false,
    buildVorbisComment("binary101", ["TITLE=Test track", "ARTIST=Coder"])
  );
  const seekTable = wrapBlock(3, false, buildSeekTable());
  const picture = wrapBlock(6, true, buildPictureBlock());
  const blocks = [streamInfo, vorbis, seekTable, picture];
  const audioTail = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
  const totalLength = 4 + blocks.reduce((sum, block) => sum + block.length, 0) + audioTail.length;
  const bytes = new Uint8Array(totalLength);
  bytes.set([0x66, 0x4c, 0x61, 0x43], 0);
  let offset = 4;
  blocks.forEach(block => {
    bytes.set(block, offset);
    offset += block.length;
  });
  bytes.set(audioTail, offset);
  return new MockFile(bytes, "sample.flac", "audio/flac");
};

export const createTruncatedFlacFile = (): MockFile => {
  const payload = new Uint8Array(8).fill(0);
  const block = wrapBlock(0, true, payload);
  const bytes = new Uint8Array(4 + block.length - 4); // drop tail to truncate
  bytes.set([0x66, 0x4c, 0x61, 0x43], 0);
  bytes.set(block.slice(0, block.length - 4), 4);
  return new MockFile(bytes, "truncated.flac", "audio/flac");
};
