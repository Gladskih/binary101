"use strict";

import { MockFile } from "../helpers/mock-file.js";
import {
  concatParts,
  ebmlElement,
  ebmlFloat,
  ebmlString,
  ebmlUInt,
  simpleBlock
} from "./webm-fixture-helpers.js";

const block = (track: number, timecode: number, flags: number, payload: Uint8Array): Uint8Array => {
  const out = new Uint8Array(1 + 2 + 1 + payload.length);
  out[0] = 0x80 | (track & 0x7f);
  const tc = new DataView(out.buffer, out.byteOffset + 1, 2);
  tc.setInt16(0, timecode, false);
  out[3] = flags;
  out.set(payload, 4);
  return ebmlElement(0xa1, out);
};

const blockGroup = (blockBytes: Uint8Array, durationTimecode: number): Uint8Array => {
  const blockDuration = ebmlUInt(0x9b, durationTimecode, 2);
  return ebmlElement(0xa0, concatParts([blockBytes, blockDuration]));
};

export const createWebmWithDurationMismatch = () => {
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

  const timecodeScale = ebmlUInt(0x2ad7b1, 1000000, 3);
  const duration = ebmlFloat(0x4489, 2000, 8);
  const info = ebmlElement(0x1549a966, concatParts([timecodeScale, duration]));

  const videoTrack = ebmlElement(
    0xae,
    concatParts([
      ebmlUInt(0xd7, 1, 1),
      ebmlUInt(0x73c5, 1, 1),
      ebmlUInt(0x83, 1, 1),
      ebmlString(0x86, "V_VP9"),
      ebmlUInt(0x23e383, 1000000000, 4)
    ])
  );

  const audioTrack = ebmlElement(
    0xae,
    concatParts([
      ebmlUInt(0xd7, 2, 1),
      ebmlUInt(0x73c5, 2, 1),
      ebmlUInt(0x83, 2, 1),
      ebmlString(0x86, "A_OPUS")
    ])
  );

  const tracks = ebmlElement(0x1654ae6b, concatParts([videoTrack, audioTrack]));

  const clusterTimecode = ebmlUInt(0xe7, 0, 1);
  const videoBlock = simpleBlock(1, 0, 0x80, new Uint8Array([0x00]));
  const audioBlock = block(2, 0, 0x00, new Uint8Array([0x00]));
  const audioGroup = blockGroup(audioBlock, 2500);
  const cluster = ebmlElement(0x1f43b675, concatParts([clusterTimecode, videoBlock, audioGroup]));

  const segmentPayload = concatParts([info, tracks, cluster]);
  const segment = ebmlElement(0x18538067, segmentPayload);
  const bytes = concatParts([ebmlHeader, segment]);
  return new MockFile(bytes, "duration-mismatch.webm", "video/webm");
};

