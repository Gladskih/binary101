"use strict";

import { MockFile } from "../helpers/mock-file.js";
import {
  concatParts,
  ebmlElement,
  ebmlString,
  ebmlUInt,
  simpleBlock
} from "./webm-fixture-helpers.js";

const createVp8KeyframePayload = (width: number, height: number): Uint8Array => {
  const payload = new Uint8Array(10);
  payload[0] = 0x10; // keyframe, version 0, show_frame=1, partition length low bits
  payload[1] = 0x00;
  payload[2] = 0x00;
  payload[3] = 0x9d;
  payload[4] = 0x01;
  payload[5] = 0x2a;
  const packedWidth = width & 0x3fff;
  const packedHeight = height & 0x3fff;
  payload[6] = packedWidth & 0xff;
  payload[7] = (packedWidth >> 8) & 0xff;
  payload[8] = packedHeight & 0xff;
  payload[9] = (packedHeight >> 8) & 0xff;
  return payload;
};

export const createWebmWithVariableVp8FrameSizes = () => {
  const ebmlHeader = ebmlElement(
    0x1a45dfa3,
    concatParts([
      ebmlUInt(0x4286, 1, 1),
      ebmlUInt(0x42f7, 1, 1),
      ebmlUInt(0x42f2, 4, 1),
      ebmlUInt(0x42f3, 8, 1),
      ebmlString(0x4282, "webm"),
      ebmlUInt(0x4287, 4, 1),
      ebmlUInt(0x4285, 2, 1)
    ])
  );

  const info = ebmlElement(0x1549a966, ebmlUInt(0x2ad7b1, 1000000, 3));

  const videoSettings = ebmlElement(
    0xe0,
    concatParts([
      ebmlUInt(0xb0, 632, 2),
      ebmlUInt(0xba, 388, 2),
      ebmlUInt(0x54b0, 690, 2),
      ebmlUInt(0x54ba, 388, 2)
    ])
  );

  const videoTrack = ebmlElement(
    0xae,
    concatParts([
      ebmlUInt(0xd7, 1, 1),
      ebmlUInt(0x73c5, 1, 1),
      ebmlUInt(0x83, 1, 1),
      ebmlString(0x86, "V_VP8"),
      videoSettings
    ])
  );

  const tracks = ebmlElement(0x1654ae6b, videoTrack);

  const cluster = ebmlElement(
    0x1f43b675,
    concatParts([
      ebmlUInt(0xe7, 0, 1),
      simpleBlock(1, 0, 0x80, createVp8KeyframePayload(632, 388)),
      simpleBlock(1, 33, 0x80, createVp8KeyframePayload(640, 360)),
      simpleBlock(1, 66, 0x80, createVp8KeyframePayload(704, 396))
    ])
  );

  const segmentPayload = concatParts([info, tracks, cluster]);
  const segment = ebmlElement(0x18538067, segmentPayload);
  const bytes = concatParts([ebmlHeader, segment]);
  return new MockFile(bytes, "vp8-variable-sizes.webm", "video/webm");
};

