"use strict";

export const ID3_HEADER_SIZE = 10;
export const ID3V1_SIZE = 128;
export const MAX_ID3V2_FRAMES = 32;
export const MAX_FRAME_SCAN = 262144;
export const MAX_EMBEDDED_IMAGE_BYTES = 5_000_000;

export const MPEG_VERSION: Map<number, string> = new Map([
  [0x0, "MPEG Version 2.5"],
  [0x2, "MPEG Version 2"],
  [0x3, "MPEG Version 1"]
]);

export const MPEG_LAYER: Map<number, string> = new Map([
  [0x1, "Layer III"],
  [0x2, "Layer II"],
  [0x3, "Layer I"]
]);

export const CHANNEL_MODE: Map<number, string> = new Map([
  [0x0, "Stereo"],
  [0x1, "Joint stereo"],
  [0x2, "Dual channel"],
  [0x3, "Single channel"]
]);

export const EMPHASIS: Map<number, string> = new Map([
  [0x0, "None"],
  [0x1, "50/15 ms"],
  [0x2, "Reserved"],
  [0x3, "CCIT J.17"]
]);

export const MODE_EXTENSION_LAYER_III: Map<number, string> = new Map([
  [0x0, "None"],
  [0x1, "Intensity stereo"],
  [0x2, "MS stereo"],
  [0x3, "Intensity + MS stereo"]
]);

export const PICTURE_TYPES: readonly string[] = [
  "Other",
  "32x32 icon",
  "Other icon",
  "Front cover",
  "Back cover",
  "Leaflet",
  "Media",
  "Lead artist",
  "Artist",
  "Conductor",
  "Band",
  "Composer",
  "Lyricist",
  "Recording location",
  "During recording",
  "During performance",
  "Screen capture",
  "Bright colored fish",
  "Illustration",
  "Band logotype",
  "Publisher logotype"
];

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

export const ID3V1_GENRES = [
  "Blues",
  "Classic rock",
  "Country",
  "Dance",
  "Disco",
  "Funk",
  "Grunge",
  "Hip-Hop",
  "Jazz",
  "Metal",
  "New age",
  "Oldies",
  "Other",
  "Pop",
  "R&B",
  "Rap",
  "Reggae",
  "Rock",
  "Techno",
  "Industrial",
  "Alternative",
  "Ska",
  "Death metal",
  "Pranks",
  "Soundtrack",
  "Euro-techno",
  "Ambient",
  "Trip-hop",
  "Vocal",
  "Jazz+Funk",
  "Fusion",
  "Trance",
  "Classical",
  "Instrumental",
  "Acid",
  "House",
  "Game",
  "Sound clip",
  "Gospel",
  "Noise",
  "Alternative rock",
  "Bass",
  "Soul",
  "Punk",
  "Space",
  "Meditative",
  "Instrumental pop",
  "Instrumental rock",
  "Ethnic",
  "Gothic",
  "Darkwave",
  "Techno-industrial",
  "Electronic",
  "Pop-folk",
  "Eurodance",
  "Dream",
  "Southern rock",
  "Comedy",
  "Cult",
  "Gangsta",
  "Top 40",
  "Christian rap",
  "Pop/funk",
  "Jungle",
  "Native American",
  "Cabaret",
  "New wave",
  "Psychedelic",
  "Rave",
  "Showtunes",
  "Trailer",
  "Lo-fi",
  "Tribal",
  "Acid punk",
  "Acid jazz",
  "Polka",
  "Retro",
  "Musical",
  "Rock & roll",
  "Hard rock"
];
