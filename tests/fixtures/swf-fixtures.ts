import { deflateSync } from "node:zlib";
import { MockFile } from "../helpers/mock-file.js";
import { createPePlusFile } from "./sample-files-pe.js";

// Adobe SWF v19, chapters 1-2: RECT is big-endian bits; scalar integers are little-endian.
// https://open-flash.github.io/mirrors/swf-spec-19.pdf
export const createSwfTag = (code: number, payload = new Uint8Array()): Uint8Array => {
  const headerLength = payload.length < 63 ? 2 : 6;
  const bytes = new Uint8Array(headerLength + payload.length);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, code * 64 + Math.min(payload.length, 63), true);
  if (headerLength === 6) view.setUint32(2, payload.length, true);
  bytes.set(payload, headerLength);
  return bytes;
};

export const createSwf = (
  extraTags: Uint8Array[] = [], bounds: readonly [number, number, number, number] = [0, 12800, 0, 9600]
): Uint8Array => {
  // 640x480 pixels, in twips (20 twips/pixel), with signed 15-bit coordinates.
  const bits = "01111" + bounds.map(value => (value & 0x7fff).toString(2).padStart(15, "0")).join("");
  const rectangle = Uint8Array.from(bits.padEnd(72, "0").match(/.{8}/g)!.map(value => parseInt(value, 2)));
  const tags = [createSwfTag(69, Uint8Array.of(8, 0, 0, 0)), ...extraTags,
    createSwfTag(1), createSwfTag(0)];
  const bytes = new Uint8Array(8 + rectangle.length + 4 + tags.reduce((size, tag) => size + tag.length, 0));
  const view = new DataView(bytes.buffer);
  bytes.set([0x46, 0x57, 0x53, 9]); // FWS, SWF 9.
  view.setUint32(4, bytes.length, true);
  bytes.set(rectangle, 8);
  view.setUint16(8 + rectangle.length, 30 * 256, true); // 8.8 fixed-point frame rate.
  view.setUint16(10 + rectangle.length, 1, true);
  let offset = 12 + rectangle.length;
  for (const tag of tags) {
    bytes.set(tag, offset);
    offset += tag.length;
  }
  return bytes;
};

export const createCws = (swf = createSwf()): Uint8Array => {
  const compressed = deflateSync(swf.subarray(8));
  const bytes = new Uint8Array(8 + compressed.length);
  bytes.set(swf.subarray(0, 8));
  bytes[0] = 0x43; // CWS: only the bytes after the fixed 8-byte header are zlib-compressed.
  bytes.set(compressed, 8);
  return bytes;
};

export const createZws = (): Uint8Array => {
  // Independent LZMA-JS encoder, mode 6, over createSwf().subarray(8), including the end marker.
  // https://github.com/LZMA-JS/LZMA-JS/blob/master/src/lzma_worker.js
  const packed = Buffer.from("003bfffcc40f05eb136019f63b02c9e687c9a2911fa445fffffc5bf000", "hex");
  const bytes = new Uint8Array(17 + packed.length);
  bytes.set(createSwf().subarray(0, 8));
  bytes[0] = 0x5a;
  bytes[3] = 13; // ZWS is defined from SWF 13 onward.
  new DataView(bytes.buffer).setUint32(8, packed.length, true);
  bytes.set([0x5d, 0, 0, 0x40, 0], 12);
  bytes.set(packed, 17);
  return bytes;
};

export const createFlashProjector = (swf = createSwf(), stubSize = 128): MockFile => {
  const bytes = new Uint8Array(stubSize + swf.length + 8);
  bytes.set(swf, stubSize);
  const view = new DataView(bytes.buffer);
  // Projector trailer convention, independent of the SWF spec:
  // https://github.com/laenion/dump_projector/blob/master/dump_projector.c
  view.setUint32(bytes.length - 8, 0xfa123456, true);
  view.setUint32(bytes.length - 4, swf.length, true);
  return new MockFile(bytes, "carrier.exe");
};

export const createFlashProjectorPe = (swf = createSwf()): MockFile => {
  const pe = createPePlusFile();
  const bytes = createFlashProjector(swf, pe.size).data.slice();
  bytes.set(pe.data);
  return new MockFile(bytes, "projector.exe");
};
