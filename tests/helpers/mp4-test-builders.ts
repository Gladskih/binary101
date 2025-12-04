"use strict";

const encoder = new TextEncoder();

export const concatParts = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const part of parts) {
    out.set(part, cursor);
    cursor += part.length;
  }
  return out;
};

export const u32be = (value: number): Uint8Array => {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, false);
  return out;
};

export const makeBox = (type: string, payload: Uint8Array): Uint8Array => {
  const size = payload.length + 8;
  const out = new Uint8Array(size);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, size, false);
  out.set(encoder.encode(type), 4);
  out.set(payload, 8);
  return out;
};

export const makeFullBox = (type: string, version: number, flags: number, payload: Uint8Array): Uint8Array => {
  const header = new Uint8Array(4);
  const dv = new DataView(header.buffer);
  dv.setUint8(0, version);
  dv.setUint8(1, (flags >> 16) & 0xff);
  dv.setUint8(2, (flags >> 8) & 0xff);
  dv.setUint8(3, flags & 0xff);
  return makeBox(type, concatParts([header, payload]));
};

export const buildSampleEntry = (format: string, body: Uint8Array, children: Uint8Array[]): Uint8Array => {
  const childBytes = children.reduce((sum, child) => sum + child.length, 0);
  const entrySize = 8 + body.length + childBytes;
  const entry = new Uint8Array(entrySize);
  const dv = new DataView(entry.buffer);
  dv.setUint32(0, entrySize, false);
  entry.set(encoder.encode(format), 4);
  entry.set(body, 8);
  let offset = 8 + body.length;
  for (const child of children) {
    entry.set(child, offset);
    offset += child.length;
  }
  return entry;
};

export const buildEsdsBox = (): Uint8Array => {
  const audioSpecific = new Uint8Array([0x11, 0x90]);
  const decoderSpecific = concatParts([new Uint8Array([0x05, audioSpecific.length]), audioSpecific]);
  const decConfigPayload = concatParts([
    new Uint8Array([0x40, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    decoderSpecific
  ]);
  const decoderConfig = concatParts([new Uint8Array([0x04, decConfigPayload.length]), decConfigPayload]);
  const slConfig = new Uint8Array([0x06, 0x01, 0x02]);
  const esDescriptor = concatParts([
    new Uint8Array([0x03, decoderConfig.length + slConfig.length + 3, 0x00, 0x02, 0x00]),
    decoderConfig,
    slConfig
  ]);
  return makeFullBox("esds", 0, 0, esDescriptor);
};

export const buildAudioSampleEntry = (): Uint8Array => {
  const body = new Uint8Array(28).fill(0);
  const dv = new DataView(body.buffer);
  dv.setUint16(6, 1, false);
  dv.setUint16(16, 2, false);
  dv.setUint16(18, 16, false);
  dv.setUint32(24, 48000 << 16, false);
  return buildSampleEntry("mp4a", body, [buildEsdsBox()]);
};

export const buildVideoSampleEntry = (): Uint8Array => {
  const body = new Uint8Array(78).fill(0);
  const dv = new DataView(body.buffer);
  dv.setUint16(6, 1, false);
  dv.setUint16(24, 640, false);
  dv.setUint16(26, 360, false);
  dv.setUint32(28, 0x00480000, false);
  dv.setUint32(32, 0x00480000, false);
  dv.setUint16(40, 1, false);
  dv.setUint8(42, 4);
  body.set(encoder.encode("H264"), 43);
  dv.setUint16(74, 0x0018, false);
  dv.setInt16(76, -1, false);
  const avcC = makeBox("avcC", new Uint8Array([0x01, 0x42, 0x00, 0x1e, 0xff]));
  const paspPayload = new Uint8Array(8);
  const paspDv = new DataView(paspPayload.buffer);
  paspDv.setUint32(0, 4, false);
  paspDv.setUint32(4, 3, false);
  const pasp = makeBox("pasp", paspPayload);
  return buildSampleEntry("avc1", body, [avcC, pasp]);
};

export const buildStsdBox = (entries: Uint8Array[]): Uint8Array => {
  const entryCount = u32be(entries.length);
  const payload = concatParts([entryCount, ...entries]);
  return makeFullBox("stsd", 0, 0, payload);
};

export const buildSttsBox = (sampleCount: number, delta: number): Uint8Array =>
  makeFullBox("stts", 0, 0, concatParts([u32be(1), u32be(sampleCount), u32be(delta)]));

export const buildStszBox = (sampleSize: number, sampleCount: number): Uint8Array => {
  const table = sampleSize === 0 ? new Uint8Array(sampleCount * 4) : new Uint8Array(0);
  return makeFullBox("stsz", 0, 0, concatParts([u32be(sampleSize), u32be(sampleCount), table]));
};

export const buildStcoBox = (count: number): Uint8Array =>
  makeFullBox("stco", 0, 0, concatParts([u32be(count), new Uint8Array(count * 4)]));

export const buildCo64Box = (count: number): Uint8Array =>
  makeFullBox("co64", 0, 0, concatParts([u32be(count), new Uint8Array(count * 8)]));

export const buildStssBox = (count: number): Uint8Array =>
  makeFullBox("stss", 0, 0, concatParts([u32be(count), new Uint8Array(count * 4)]));

export const buildTkhdBox = (
  trackId: number,
  duration: number,
  width: number,
  height: number,
  volume: number
): Uint8Array => {
  const payload = new Uint8Array(80).fill(0);
  const dv = new DataView(payload.buffer);
  dv.setUint32(0, 0, false);
  dv.setUint32(4, 0, false);
  dv.setUint32(8, trackId >>> 0, false);
  dv.setUint32(16, duration >>> 0, false);
  dv.setUint16(28, 0, false);
  dv.setUint16(30, 0, false);
  dv.setUint16(32, volume, false);
  dv.setUint32(36, 0x00010000, false);
  dv.setUint32(52, 0x00010000, false);
  dv.setUint32(68, 0x40000000, false);
  dv.setUint32(72, width << 16, false);
  dv.setUint32(76, height << 16, false);
  return makeFullBox("tkhd", 0, 0x000007, payload);
};

export const buildMdhdBox = (timescale: number, duration: number): Uint8Array => {
  const payload = new Uint8Array(20).fill(0);
  const dv = new DataView(payload.buffer);
  dv.setUint32(8, timescale >>> 0, false);
  dv.setUint32(12, duration >>> 0, false);
  dv.setUint16(16, 0x15c7, false);
  return makeFullBox("mdhd", 0, 0, payload);
};

export const buildHdlrBox = (handler: string, name: string): Uint8Array => {
  const nameBytes = encoder.encode(name);
  const payload = concatParts([
    u32be(0),
    encoder.encode(handler),
    new Uint8Array(12).fill(0),
    nameBytes,
    new Uint8Array([0])
  ]);
  return makeFullBox("hdlr", 0, 0, payload);
};

export const buildMdiaBox = (
  handler: string,
  name: string,
  timescale: number,
  duration: number,
  stbl: Uint8Array
): Uint8Array =>
  makeBox(
    "mdia",
    concatParts([buildMdhdBox(timescale, duration), buildHdlrBox(handler, name), makeBox("minf", stbl)])
  );

export const buildTrakBox = (
  handler: string,
  name: string,
  timescale: number,
  duration: number,
  stbl: Uint8Array
): Uint8Array =>
  makeBox(
    "trak",
    concatParts([
      buildTkhdBox(3, duration, 320, 180, handler === "soun" ? 0x0100 : 0),
      buildMdiaBox(handler, name, timescale, duration, stbl)
    ])
  );
