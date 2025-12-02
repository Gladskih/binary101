"use strict";

import { MockFile } from "../helpers/mock-file.js";

export const createMp3File = () => {
  const versionBits = 0x3;
  const layerBits = 0x1;
  const bitrateIndex = 0x9; // 128 kbps
  const sampleRateIndex = 0x0; // 44100
  const header =
    (0x7ff << 21) |
    (versionBits << 19) |
    (layerBits << 17) |
    (1 << 16) | // no CRC
    (bitrateIndex << 12) |
    (sampleRateIndex << 10) |
    (0 << 9) | // padding
    (0 << 6) | // channel mode stereo
    (0 << 4) |
    (0 << 2) |
    0;
  const frameLength = Math.floor((1152 * 128000) / (8 * 44100));
  const totalLength = frameLength * 2;
  const bytes = new Uint8Array(totalLength).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, header, false);
  view.setUint32(frameLength, header, false);
  return new MockFile(bytes, "sample.mp3", "audio/mpeg");
};
