"use strict";

import { MockFile } from "../helpers/mock-file.js";

const fromHex = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex.replace(/\s+/g, ""), "hex"));

// Minimal VP8X with canvas and an ANIM chunk but no frame data
export const createAnimatedWebpMissingFrame = () =>
  new MockFile(
    fromHex(
      "52494646" + // RIFF
        "1A000000" + // size 26+8
        "57454250" + // WEBP
        "56503858" + // VP8X
        "0A000000" + // chunk size 10
        "02" + // flags: animation
        "000000" + // reserved
        "010000" + // width-1
        "010000" + // height-1
        "414e494d" + // ANIM
        "06000000" + // size 6
        "00000000" + // background color
        "0000" // loop count
    ),
    "anim-missing-frame.webp",
    "image/webp"
  );
