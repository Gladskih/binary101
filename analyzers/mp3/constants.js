"use strict";

export const ID3_HEADER_SIZE = 10;
export const ID3V1_SIZE = 128;
export const MAX_ID3V2_FRAMES = 32;
export const MAX_FRAME_SCAN = 262144;

export const MPEG_VERSION = new Map([
  [0x0, "MPEG Version 2.5"],
  [0x2, "MPEG Version 2"],
  [0x3, "MPEG Version 1"]
]);

export const MPEG_LAYER = new Map([
  [0x1, "Layer III"],
  [0x2, "Layer II"],
  [0x3, "Layer I"]
]);

export const CHANNEL_MODE = new Map([
  [0x0, "Stereo"],
  [0x1, "Joint stereo"],
  [0x2, "Dual channel"],
  [0x3, "Single channel"]
]);

export const EMPHASIS = new Map([
  [0x0, "None"],
  [0x1, "50/15 ms"],
  [0x2, "Reserved"],
  [0x3, "CCIT J.17"]
]);

export const SAMPLE_RATES = {
  0x3: [44100, 48000, 32000],
  0x2: [22050, 24000, 16000],
  0x0: [11025, 12000, 8000]
};

export const BITRATES = {
  0x3: {
    0x3: [
      null, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448
    ],
    0x2: [
      null, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384
    ],
    0x1: [
      null, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320
    ]
  },
  0x2: {
    0x3: [
      null, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256
    ],
    0x2: [
      null, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160
    ],
    0x1: [
      null, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160
    ]
  },
  0x0: {
    0x3: [
      null, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256
    ],
    0x2: [
      null, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160
    ],
    0x1: [
      null, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160
    ]
  }
};

export const XING_FLAG_FRAMES = 0x00000001;
export const XING_FLAG_BYTES = 0x00000002;
export const XING_FLAG_TOC = 0x00000004;
export const XING_FLAG_QUALITY = 0x00000008;
