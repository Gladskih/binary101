"use strict";

import { MockFile } from "../helpers/mock-file.js";
import { concatParts, ebmlElement, ebmlFloat, ebmlString, ebmlUInt } from "./webm-fixture-helpers.js";

export const createWebmWithInvalidCodecs = () => {
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
      ebmlString(0x86, "V_MS/VFW/FOURCC")
    ])
  );

  const audioTrack = ebmlElement(
    0xae,
    concatParts([
      ebmlUInt(0xd7, 2, 1),
      ebmlUInt(0x73c5, 2, 1),
      ebmlUInt(0x83, 2, 1),
      ebmlString(0x86, "A_MPEG/L3")
    ])
  );

  const tracks = ebmlElement(0x1654ae6b, concatParts([videoTrack, audioTrack]));
  const segmentPayload = concatParts([info, tracks]);
  const segment = ebmlElement(0x18538067, segmentPayload);
  const bytes = concatParts([ebmlHeader, segment]);
  return new MockFile(bytes, "invalid-codec.webm", "video/webm");
};
