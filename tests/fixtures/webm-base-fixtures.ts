"use strict";

import { MockFile } from "../helpers/mock-file.js";
import { concatParts, ebmlElement, ebmlFloat, ebmlString, ebmlUInt, encodeEbmlId } from "./webm-fixture-helpers.js";

export const createWebmFile = () => {
  const ebmlHeader = ebmlElement(
    0x1a45dfa3,
    concatParts([
      ebmlUInt(0x4286, 1, 1), // EBMLVersion
      ebmlUInt(0x42f7, 1, 1), // EBMLReadVersion
      ebmlUInt(0x42f2, 4, 1), // EBMLMaxIDLength
      ebmlUInt(0x42f3, 8, 1), // EBMLMaxSizeLength
      ebmlString(0x4282, "webm"),
      ebmlUInt(0x4287, 4, 1), // DocTypeVersion
      ebmlUInt(0x4285, 2, 1) // DocTypeReadVersion
    ])
  );

  const timecodeScale = ebmlUInt(0x2ad7b1, 1000000, 3); // ns
  const duration = ebmlFloat(0x4489, 2000, 8); // 2 seconds with default scale
  const muxingApp = ebmlString(0x4d80, "binary101-tests");
  const writingApp = ebmlString(0x5741, "binary101-webm");
  const title = ebmlString(0x7ba9, "Example WebM");
  const info = ebmlElement(0x1549a966, concatParts([timecodeScale, duration, muxingApp, writingApp, title]));

  const videoSettings = ebmlElement(
    0xe0,
    concatParts([
      ebmlUInt(0xb0, 320, 2), // PixelWidth
      ebmlUInt(0xba, 240, 2), // PixelHeight
      ebmlUInt(0x54b0, 320, 2), // DisplayWidth
      ebmlUInt(0x54ba, 240, 2), // DisplayHeight
      ebmlUInt(0x54bb, 1, 1), // PixelCropTop
      ebmlUInt(0x54aa, 2, 1), // PixelCropBottom
      ebmlUInt(0x54cc, 3, 1), // PixelCropLeft
      ebmlUInt(0x54dd, 4, 1) // PixelCropRight
    ])
  );

  const videoTrack = ebmlElement(
    0xae,
    concatParts([
      ebmlUInt(0xd7, 1, 1), // TrackNumber
      ebmlUInt(0x73c5, 1, 1), // TrackUID
      ebmlUInt(0x83, 1, 1), // TrackType video
      ebmlUInt(0x88, 1, 1), // FlagDefault
      ebmlUInt(0xb9, 1, 1), // FlagEnabled
      ebmlUInt(0x9c, 0, 1), // FlagLacing off
      ebmlUInt(0x23e383, 41666666, 4), // DefaultDuration ~24 fps
      ebmlString(0x86, "V_VP8"),
      ebmlString(0x536e, "Video track"),
      videoSettings
    ])
  );

  const audioSettings = ebmlElement(
    0xe1,
    concatParts([
      ebmlFloat(0xb5, 48000, 8), // SamplingFrequency
      ebmlUInt(0x9f, 2, 1), // Channels
      ebmlUInt(0x6264, 16, 1) // BitDepth
    ])
  );

  const audioTrack = ebmlElement(
    0xae,
    concatParts([
      ebmlUInt(0xd7, 2, 1),
      ebmlUInt(0x73c5, 2, 1),
      ebmlUInt(0x83, 2, 1), // TrackType audio
      ebmlUInt(0x88, 1, 1),
      ebmlUInt(0xb9, 1, 1),
      ebmlString(0x86, "A_OPUS"),
      ebmlString(0x536e, "Audio track"),
      audioSettings
    ])
  );

  const tracks = ebmlElement(0x1654ae6b, concatParts([videoTrack, audioTrack]));

  const buildSeekHead = (infoOffset: number, tracksOffset: number): Uint8Array => {
    const seekInfo = ebmlElement(
      0x4dbb,
      concatParts([
        ebmlElement(0x53ab, encodeEbmlId(0x1549a966)),
        ebmlUInt(0x53ac, infoOffset, 2)
      ])
    );
    const seekTracks = ebmlElement(
      0x4dbb,
      concatParts([
        ebmlElement(0x53ab, encodeEbmlId(0x1654ae6b)),
        ebmlUInt(0x53ac, tracksOffset, 2)
      ])
    );
    return ebmlElement(0x114d9b74, concatParts([seekInfo, seekTracks]));
  };

  let seekHead = buildSeekHead(0, 0);
  for (let i = 0; i < 4; i += 1) {
    const infoOffset = seekHead.length;
    const tracksOffset = seekHead.length + info.length;
    const rebuilt = buildSeekHead(infoOffset, tracksOffset);
    if (rebuilt.length === seekHead.length) break;
    seekHead = rebuilt;
  }

  const segmentPayload = concatParts([seekHead, info, tracks]);
  const segment = ebmlElement(0x18538067, segmentPayload);
  const bytes = concatParts([ebmlHeader, segment]);
  return new MockFile(bytes, "sample.webm", "video/webm");
};
