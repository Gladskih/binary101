"use strict";

import { MockFile } from "../helpers/mock-file.js";

export type RiffChunkSpec = {
  id: string;
  data?: Uint8Array;
  children?: RiffChunkSpec[];
  listType?: string;
};

const ANI_HEADER_SIZE = 36;

const fourCcBytes = (fourCc: string): Uint8Array => {
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i += 1) {
    const code = fourCc.charCodeAt(i) || 0x20;
    bytes[i] = code & 0xff;
  }
  return bytes;
};

const concatArrays = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
};

const encodeChunk = (spec: RiffChunkSpec): Uint8Array => {
  let payload: Uint8Array;
  if (spec.children && spec.children.length > 0) {
    const listType = fourCcBytes(spec.listType || "    ");
    const childBytes = spec.children.map(encodeChunk);
    payload = concatArrays([listType, ...childBytes]);
  } else {
    payload = spec.data || new Uint8Array();
  }
  const padded =
    payload.length % 2 === 0 ? payload : concatArrays([payload, new Uint8Array([0])]);
  const header = new Uint8Array(8);
  header.set(fourCcBytes(spec.id), 0);
  new DataView(header.buffer).setUint32(4, payload.length, true);
  return concatArrays([header, padded]);
};

const buildRiffBytes = (formType: string, chunks: RiffChunkSpec[]): Uint8Array => {
  const body = concatArrays(chunks.map(encodeChunk));
  const riffSize = 4 + body.length;
  const header = new Uint8Array(12);
  header.set(fourCcBytes("RIFF"), 0);
  new DataView(header.buffer).setUint32(4, riffSize, true);
  header.set(fourCcBytes(formType), 8);
  return concatArrays([header, body]);
};

export const buildRiffFile = (
  formType: string,
  chunks: RiffChunkSpec[],
  name: string,
  type: string
): MockFile => new MockFile(buildRiffBytes(formType, chunks), name, type);

export const createSimpleRiff = (): MockFile =>
  buildRiffFile(
    "TEST",
    [{ id: "TEST", data: new Uint8Array([1, 2, 3, 4]) }],
    "sample.riff",
    "application/octet-stream"
  );

export const createNestedRiff = (): MockFile =>
  buildRiffFile(
    "TEST",
    [
      {
        id: "LIST",
        listType: "INFO",
        children: [
          { id: "INAM", data: new Uint8Array([0x41, 0x42, 0x00]) },
          { id: "ICMT", data: new Uint8Array([0x63, 0x6d, 0x74]) }
        ]
      }
    ],
    "nested.riff",
    "application/octet-stream"
  );

export const createWavFile = (): MockFile => {
  const fmt = new Uint8Array(16);
  const fmtView = new DataView(fmt.buffer);
  fmtView.setUint16(0, 1, true); // PCM
  fmtView.setUint16(2, 1, true); // mono
  fmtView.setUint32(4, 8000, true);
  fmtView.setUint32(8, 8000, true); // byte rate (8000 * 1 * 8/8)
  fmtView.setUint16(12, 1, true); // block align
  fmtView.setUint16(14, 8, true); // bits per sample
  const data = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
  return buildRiffFile(
    "WAVE",
    [
      { id: "fmt ", data: fmt },
      { id: "data", data }
    ],
    "sample.wav",
    "audio/wav"
  );
};

export const createAviFile = (): MockFile => {
  const avih = new Uint8Array(56);
  const avihView = new DataView(avih.buffer);
  avihView.setUint32(0, 40_000, true); // microseconds per frame (25 fps)
  avihView.setUint32(4, 100_000, true);
  avihView.setUint32(16, 10, true); // total frames
  avihView.setUint32(24, 1, true); // streams
  avihView.setUint32(32, 320, true); // width
  avihView.setUint32(36, 240, true); // height

  const strh = new Uint8Array(64);
  const strhView = new DataView(strh.buffer);
  strh.set(fourCcBytes("vids"), 0);
  strh.set(fourCcBytes("MJPG"), 4);
  strhView.setUint32(16, 0, true); // initialFrames
  strhView.setUint32(20, 1, true); // scale
  strhView.setUint32(24, 25, true); // rate (25 fps)
  strhView.setUint32(32, 10, true); // length
  strhView.setInt32(56, 320, true); // rcFrame right
  strhView.setInt32(60, 240, true); // rcFrame bottom

  const strf = new Uint8Array(24);
  const strfView = new DataView(strf.buffer);
  strfView.setUint32(0, 40, true); // BITMAPINFOHEADER size
  strfView.setInt32(4, 320, true);
  strfView.setInt32(8, 240, true);
  strfView.setUint16(12, 1, true); // planes
  strfView.setUint16(14, 24, true); // bits per pixel
  strf.set(fourCcBytes("MJPG"), 16);
  strfView.setUint32(20, 0, true);
  const strn = new Uint8Array([0x43, 0x61, 0x6d, 0x20, 0x31, 0x00]);

  const hdrl: RiffChunkSpec = {
    id: "LIST",
    listType: "hdrl",
    children: [
      { id: "avih", data: avih },
      {
        id: "LIST",
        listType: "strl",
        children: [
          { id: "strh", data: strh },
          { id: "strf", data: strf },
          { id: "strn", data: strn }
        ]
      }
    ]
  };

  const movi: RiffChunkSpec = {
    id: "LIST",
    listType: "movi",
    children: []
  };

  return buildRiffFile(
    "AVI ",
    [hdrl, movi],
    "sample.avi",
    "video/x-msvideo"
  );
};

export const createAniFile = (): MockFile => {
  const anih = new Uint8Array(ANI_HEADER_SIZE);
  const view = new DataView(anih.buffer);
  view.setUint32(0, ANI_HEADER_SIZE, true);
  view.setUint32(4, 2, true); // frames
  view.setUint32(8, 2, true); // steps
  view.setUint32(12, 32, true);
  view.setUint32(16, 32, true);
  view.setUint32(20, 32, true);
  view.setUint32(24, 1, true);
  view.setUint32(28, 6, true); // jif rate
  view.setUint32(32, 0x3, true); // flags icon+sequence

  const rate = new Uint8Array(8);
  const rateView = new DataView(rate.buffer);
  rateView.setUint32(0, 6, true);
  rateView.setUint32(4, 6, true);

  const seq = new Uint8Array(8);
  const seqView = new DataView(seq.buffer);
  seqView.setUint32(0, 0, true);
  seqView.setUint32(4, 1, true);

  const iconData = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
  const infoList: RiffChunkSpec = {
    id: "LIST",
    listType: "INFO",
    children: [{ id: "INAM", data: new Uint8Array([0x54, 0x65, 0x73, 0x74, 0x00]) }]
  };

  return buildRiffFile(
    "ACON",
    [
      { id: "anih", data: anih },
      { id: "rate", data: rate },
      { id: "seq ", data: seq },
      { id: "icon", data: iconData },
      { id: "icon", data: iconData },
      infoList
    ],
    "sample.ani",
    "application/x-navi-animation"
  );
};
