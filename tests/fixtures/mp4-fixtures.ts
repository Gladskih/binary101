"use strict";

import { MockFile } from "../helpers/mock-file.js";

const encoder = new TextEncoder();

const concatParts = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  parts.forEach(part => {
    out.set(part, cursor);
    cursor += part.length;
  });
  return out;
};

const u16be = (value: number): Uint8Array => {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, false);
  return out;
};

const u32be = (value: number): Uint8Array => {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, false);
  return out;
};

const makeBox = (type: string, payload: Uint8Array): Uint8Array => {
  const size = payload.length + 8;
  const out = new Uint8Array(size);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, size, false);
  out.set(encoder.encode(type), 4);
  out.set(payload, 8);
  return out;
};

const makeFullBox = (type: string, version: number, flags: number, payload: Uint8Array): Uint8Array => {
  const header = new Uint8Array(4);
  const hdv = new DataView(header.buffer);
  hdv.setUint8(0, version);
  hdv.setUint8(1, (flags >> 16) & 0xff);
  hdv.setUint8(2, (flags >> 8) & 0xff);
  hdv.setUint8(3, flags & 0xff);
  return makeBox(type, concatParts([header, payload]));
};

const makeNullTerminatedAscii = (text: string): Uint8Array => {
  const data = encoder.encode(text);
  const out = new Uint8Array(data.length + 1);
  out.set(data, 0);
  out[out.length - 1] = 0;
  return out;
};

export const createMp4File = () => {
  const buildFtyp = () =>
    makeBox(
      "ftyp",
      concatParts([encoder.encode("isom"), u32be(0x200), encoder.encode("isom"), encoder.encode("mp41")])
    );

  const buildMvhd = (timescale: number, duration: number) => {
    const payload = new Uint8Array(96).fill(0);
    const dv = new DataView(payload.buffer);
    dv.setUint32(0, 0, false);
    dv.setUint32(4, 0, false);
    dv.setUint32(8, timescale >>> 0, false);
    dv.setUint32(12, duration >>> 0, false);
    dv.setUint32(16, 0x00010000, false);
    dv.setUint16(20, 0x0100, false);
    dv.setUint32(24, 0x00010000, false);
    dv.setUint32(40, 0x00010000, false);
    dv.setUint32(56, 0x40000000, false);
    dv.setUint32(92, 3, false);
    return makeFullBox("mvhd", 0, 0, payload);
  };

  const buildTkhd = (trackId: number, duration: number, width: number, height: number, volume: number) => {
    const payload = new Uint8Array(80).fill(0);
    const dv = new DataView(payload.buffer);
    dv.setUint32(0, 0, false);
    dv.setUint32(4, 0, false);
    dv.setUint32(8, trackId >>> 0, false);
    dv.setUint32(16, duration >>> 0, false);
    dv.setUint32(20, 0, false);
    dv.setUint32(24, 0, false);
    dv.setUint16(28, 0, false);
    dv.setUint16(30, 0, false);
    dv.setUint16(32, volume, false);
    dv.setUint16(34, 0, false);
    dv.setUint32(36, 0x00010000, false);
    dv.setUint32(40, 0, false);
    dv.setUint32(44, 0, false);
    dv.setUint32(48, 0, false);
    dv.setUint32(52, 0x00010000, false);
    dv.setUint32(56, 0, false);
    dv.setUint32(60, 0, false);
    dv.setUint32(64, 0, false);
    dv.setUint32(68, 0x40000000, false);
    dv.setUint32(72, width << 16, false);
    dv.setUint32(76, height << 16, false);
    return makeFullBox("tkhd", 0, 0x000007, payload);
  };

  const buildMdhd = (timescale: number, duration: number) => {
    const payload = new Uint8Array(20).fill(0);
    const dv = new DataView(payload.buffer);
    dv.setUint32(0, 0, false);
    dv.setUint32(4, 0, false);
    dv.setUint32(8, timescale >>> 0, false);
    dv.setUint32(12, duration >>> 0, false);
    dv.setUint16(16, 0x15c7, false); // "eng"
    return makeFullBox("mdhd", 0, 0, payload);
  };

  const buildHdlr = (handler: string, name: string) => {
    const nameBytes = makeNullTerminatedAscii(name);
    const payload = concatParts([u32be(0), encoder.encode(handler), new Uint8Array(12).fill(0), nameBytes]);
    return makeFullBox("hdlr", 0, 0, payload);
  };

  const buildAvc1Stsd = () => {
    const body = new Uint8Array(78).fill(0);
    const dv = new DataView(body.buffer);
    dv.setUint16(6, 1, false);
    dv.setUint16(24, 320, false);
    dv.setUint16(26, 180, false);
    dv.setUint32(28, 0x00480000, false);
    dv.setUint32(32, 0x00480000, false);
    dv.setUint16(40, 1, false);
    dv.setUint16(74, 0x0018, false);
    dv.setInt16(76, -1, false);
    const avcCPayload = new Uint8Array([
      0x01, 0x42, 0x00, 0x1e, 0xff, 0xe1, 0x00, 0x04, 0x67, 0x42,
      0x00, 0x1e, 0x01, 0x00, 0x01, 0x68, 0xce, 0x06, 0xe2, 0x0c
    ]);
    const avcC = makeBox("avcC", avcCPayload);
    const entrySize = 8 + body.length + avcC.length;
    const entry = new Uint8Array(entrySize);
    const edv = new DataView(entry.buffer);
    edv.setUint32(0, entrySize, false);
    entry.set(encoder.encode("avc1"), 4);
    entry.set(body, 8);
    entry.set(avcC, 8 + body.length);
    const entryCount = u32be(1);
    return makeFullBox("stsd", 0, 0, concatParts([entryCount, entry]));
  };

  const buildEsds = () => {
    const audioSpecific = new Uint8Array([0x11, 0x90]);
    const decoderSpecific = concatParts([new Uint8Array([0x05, audioSpecific.length]), audioSpecific]);
    const decConfigPayload = concatParts([
      new Uint8Array([
        0x40,
        0x15,
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
      ]),
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

  const buildMp4aStsd = () => {
    const body = new Uint8Array(28).fill(0);
    const dv = new DataView(body.buffer);
    dv.setUint16(6, 1, false);
    dv.setUint16(16, 2, false);
    dv.setUint16(18, 16, false);
    dv.setUint32(24, 48000 << 16, false);
    const esds = buildEsds();
    const entrySize = 8 + body.length + esds.length;
    const entry = new Uint8Array(entrySize);
    const edv = new DataView(entry.buffer);
    edv.setUint32(0, entrySize, false);
    entry.set(encoder.encode("mp4a"), 4);
    entry.set(body, 8);
    entry.set(esds, 8 + body.length);
    const entryCount = u32be(1);
    return makeFullBox("stsd", 0, 0, concatParts([entryCount, entry]));
  };

  const buildStts = (sampleCount: number, delta: number) => {
    const payload = concatParts([u32be(1), u32be(sampleCount), u32be(delta)]);
    return makeFullBox("stts", 0, 0, payload);
  };

  const buildStsz = (sampleCount: number, sizes: number[]) => {
    const table = new Uint8Array(sampleCount * 4);
    const tdv = new DataView(table.buffer);
    sizes.forEach((size, idx) => {
      tdv.setUint32(idx * 4, size >>> 0, false);
    });
    const payload = concatParts([u32be(0), u32be(sampleCount), table]);
    return makeFullBox("stsz", 0, 0, payload);
  };

  const buildStco = () => makeFullBox("stco", 0, 0, concatParts([u32be(1), u32be(0)]));

  const buildStbl = (stsd: Uint8Array, stts: Uint8Array, stsz: Uint8Array, stco: Uint8Array) =>
    makeBox("stbl", concatParts([stsd, stts, stsz, stco]));

  const buildVmhd = () => makeFullBox("vmhd", 0, 0x000001, concatParts([u16be(0), u16be(0), u16be(0), u16be(0)]));
  const buildSmhd = () => makeFullBox("smhd", 0, 0, concatParts([u16be(0), u16be(0)]));

  const buildMinf = (isVideo: boolean, stbl: Uint8Array) => {
    const header = isVideo ? buildVmhd() : buildSmhd();
    return makeBox("minf", concatParts([header, stbl]));
  };

  const buildMdia = (
    handler: string,
    name: string,
    timescale: number,
    duration: number,
    stbl: Uint8Array
  ) =>
    makeBox(
      "mdia",
      concatParts([buildMdhd(timescale, duration), buildHdlr(handler, name), buildMinf(handler === "vide", stbl)])
    );

  const buildTrak = (id: number, duration: number, width: number, height: number, volume: number, mdia: Uint8Array) =>
    makeBox("trak", concatParts([buildTkhd(id, duration, width, height, volume), mdia]));

  const stsdVideo = buildAvc1Stsd();
  const sttsVideo = buildStts(2, 90000);
  const stszVideo = buildStsz(2, [1200, 1100]);
  const stcoVideo = buildStco();
  const stsdAudio = buildMp4aStsd();
  const sttsAudio = buildStts(2, 48000);
  const stszAudio = buildStsz(2, [2000, 2000]);
  const stcoAudio = buildStco();

  const stblVideo = buildStbl(stsdVideo, sttsVideo, stszVideo, stcoVideo);
  const stblAudio = buildStbl(stsdAudio, sttsAudio, stszAudio, stcoAudio);

  const mdiaVideo = buildMdia("vide", "VideoHandler", 90000, 180000, stblVideo);
  const mdiaAudio = buildMdia("soun", "SoundHandler", 48000, 96000, stblAudio);

  const trakVideo = buildTrak(1, 2000, 320, 180, 0, mdiaVideo);
  const trakAudio = buildTrak(2, 2000, 0, 0, 0x0100, mdiaAudio);
  const moov = makeBox("moov", concatParts([buildMvhd(1000, 2000), trakVideo, trakAudio]));
  const mdat = makeBox("mdat", new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]));
  const bytes = concatParts([buildFtyp(), moov, mdat]);
  return new MockFile(bytes, "sample.mp4", "video/mp4");
};
