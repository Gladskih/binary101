"use strict";

import { MockFile } from "../helpers/mock-file.js";
import {
  concatParts,
  ebmlElement,
  ebmlFloat,
  ebmlString,
  ebmlUInt,
  encodeEbmlId,
  simpleBlock
} from "./webm-fixture-helpers.js";

export const createWebmWithCues = () => {
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
      ebmlString(0x86, "V_VP8"),
      ebmlString(0x536e, "Video track"),
      videoSettings
    ])
  );

  const audioSettings = ebmlElement(
    0xe1,
    concatParts([ebmlFloat(0xb5, 48000, 8), ebmlUInt(0x9f, 2, 1), ebmlUInt(0x6264, 16, 1)])
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
      ebmlString(0x536e, "Audio track"),
      audioSettings
    ])
  );

  const tracks = ebmlElement(0x1654ae6b, concatParts([videoTrack, audioTrack]));

  const buildCuePoint = (timecode: number, track: number, clusterPosition: number) =>
    ebmlElement(
      0xbb,
      concatParts([
        ebmlUInt(0xb3, timecode, 2),
        ebmlElement(
          0xb7,
          concatParts([
            ebmlUInt(0xf7, track, 1),
            ebmlUInt(0xf1, clusterPosition, 3),
            ebmlUInt(0xf0, 0, 1),
            ebmlUInt(0x5378, 1, 1)
          ])
        )
      ])
    );

  const buildCues = (clusterPosition: number) => {
    const cuesPayload = concatParts([buildCuePoint(0, 1, clusterPosition), buildCuePoint(1000, 2, clusterPosition)]);
    return ebmlElement(0x1c53bb6b, cuesPayload);
  };

  const clusterBlocks = concatParts([
    ebmlUInt(0xe7, 0, 1),
    simpleBlock(1, 0, 0x80, new Uint8Array([0x00])),
    simpleBlock(2, 100, 0x00, new Uint8Array([0x00]))
  ]);
  const cluster = ebmlElement(0x1f43b675, clusterBlocks);

  const buildSeekHead = (infoOffset: number, tracksOffset: number, cuesOffset: number) => {
    const seekInfo = ebmlElement(
      0x4dbb,
      concatParts([ebmlElement(0x53ab, encodeEbmlId(0x1549a966)), ebmlUInt(0x53ac, infoOffset, 2)])
    );
    const seekTracks = ebmlElement(
      0x4dbb,
      concatParts([ebmlElement(0x53ab, encodeEbmlId(0x1654ae6b)), ebmlUInt(0x53ac, tracksOffset, 2)])
    );
    const seekCues = ebmlElement(
      0x4dbb,
      concatParts([ebmlElement(0x53ab, encodeEbmlId(0x1c53bb6b)), ebmlUInt(0x53ac, cuesOffset, 2)])
    );
    return ebmlElement(0x114d9b74, concatParts([seekInfo, seekTracks, seekCues]));
  };

  let cues = buildCues(0);
  let seekHead = buildSeekHead(0, 0, 0);
  for (let i = 0; i < 4; i += 1) {
    const infoOffset = seekHead.length;
    const tracksOffset = seekHead.length + info.length;
    const cuesOffset = seekHead.length + info.length + tracks.length;
    const clusterOffset = cuesOffset + cues.length;
    const rebuiltCues = buildCues(clusterOffset);
    const rebuiltSeek = buildSeekHead(infoOffset, tracksOffset, cuesOffset);
    const stable = rebuiltCues.length === cues.length && rebuiltSeek.length === seekHead.length;
    cues = rebuiltCues;
    seekHead = rebuiltSeek;
    if (stable) break;
  }

  const segmentPayload = concatParts([seekHead, info, tracks, cues, cluster]);
  const segment = ebmlElement(0x18538067, segmentPayload);
  const bytes = concatParts([ebmlHeader, segment]);
  return new MockFile(bytes, "cues.webm", "video/webm");
};
