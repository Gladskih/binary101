"use strict";

import { MockFile } from "../helpers/mock-file.js";
import { concatParts, ebmlElement, ebmlFloat, ebmlString, ebmlUInt } from "./webm-fixture-helpers.js";

export const createWebmWithTags = () => {
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
  const muxingApp = ebmlString(0x4d80, "binary101-tests");
  const writingApp = ebmlString(0x5741, "binary101-webm");
  const info = ebmlElement(0x1549a966, concatParts([timecodeScale, muxingApp, writingApp]));

  const videoSettings = ebmlElement(0xe0, concatParts([ebmlUInt(0xb0, 320, 2), ebmlUInt(0xba, 240, 2)]));
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

  const audioSettings = ebmlElement(
    0xe1,
    concatParts([ebmlFloat(0xb5, 44100, 8), ebmlUInt(0x9f, 2, 1), ebmlUInt(0x6264, 16, 1)])
  );
  const audioTrack = ebmlElement(
    0xae,
    concatParts([
      ebmlUInt(0xd7, 2, 1),
      ebmlUInt(0x73c5, 2, 1),
      ebmlUInt(0x83, 2, 1),
      ebmlString(0x86, "A_VORBIS"),
      audioSettings
    ])
  );
  const tracks = ebmlElement(0x1654ae6b, concatParts([videoTrack, audioTrack]));

  const tagTargets = ebmlElement(0x63c0, ebmlUInt(0x63c5, 1, 1)); // TrackUID 1
  const simpleTag = ebmlElement(
    0x67c8,
    concatParts([
      ebmlString(0x45a3, "TITLE"),
      ebmlString(0x4487, "Example title"),
      ebmlString(0x447a, "eng"),
      ebmlUInt(0x4484, 1, 1)
    ])
  );
  const tag = ebmlElement(0x7373, concatParts([tagTargets, simpleTag]));
  const tags = ebmlElement(0x1254c367, tag);

  const segmentPayload = concatParts([info, tracks, tags]);
  const segment = ebmlElement(0x18538067, segmentPayload);
  const bytes = concatParts([ebmlHeader, segment]);
  return new MockFile(bytes, "tags.webm", "video/webm");
};
