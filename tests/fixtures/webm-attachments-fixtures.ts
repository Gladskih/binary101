"use strict";

import { MockFile } from "../helpers/mock-file.js";
import { concatParts, ebmlElement, ebmlFloat, ebmlString, ebmlUInt } from "./webm-fixture-helpers.js";

export const createWebmWithAttachments = () => {
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
  const muxingApp = ebmlString(0x4d80, "binary101-tests");
  const writingApp = ebmlString(0x5741, "binary101-webm");
  const title = ebmlString(0x7ba9, "Example WebM");
  const info = ebmlElement(0x1549a966, concatParts([timecodeScale, duration, muxingApp, writingApp, title]));

  const videoSettings = ebmlElement(
    0xe0,
    concatParts([
      ebmlUInt(0xb0, 320, 2),
      ebmlUInt(0xba, 240, 2),
      ebmlUInt(0x54b0, 320, 2),
      ebmlUInt(0x54ba, 240, 2)
    ])
  );
  const videoTrack = ebmlElement(
    0xae,
    concatParts([
      ebmlUInt(0xd7, 1, 1),
      ebmlUInt(0x73c5, 1, 1),
      ebmlUInt(0x83, 1, 1),
      ebmlUInt(0x88, 1, 1),
      ebmlUInt(0xb9, 1, 1),
      ebmlUInt(0x9c, 0, 1),
      ebmlUInt(0x23e383, 41666666, 4),
      ebmlString(0x86, "V_VP8"),
      videoSettings
    ])
  );
  const audioSettings = ebmlElement(
    0xe1,
    concatParts([
      ebmlFloat(0xb5, 48000, 8),
      ebmlUInt(0x9f, 2, 1),
      ebmlUInt(0x6264, 16, 1)
    ])
  );
  const audioTrack = ebmlElement(
    0xae,
    concatParts([
      ebmlUInt(0xd7, 2, 1),
      ebmlUInt(0x73c5, 2, 1),
      ebmlUInt(0x83, 2, 1),
      ebmlUInt(0x88, 1, 1),
      ebmlUInt(0xb9, 1, 1),
      ebmlString(0x86, "A_OPUS"),
      audioSettings
    ])
  );
  const tracks = ebmlElement(0x1654ae6b, concatParts([videoTrack, audioTrack]));
  const attachments = ebmlElement(0x1941a469, new Uint8Array(0));
  const segmentPayload = concatParts([info, tracks, attachments]);
  const segment = ebmlElement(0x18538067, segmentPayload);
  const bytes = concatParts([ebmlHeader, segment]);
  return new MockFile(bytes, "attachments.webm", "video/webm");
};
