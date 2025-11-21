"use strict";

import { MockFile } from "../helpers/mock-file.mjs";

const fromHex = hex => new Uint8Array(Buffer.from(hex.replace(/\s+/g, ""), "hex"));

export const createInvalidWebpSignature = () =>
  new MockFile(new Uint8Array([0x52, 0x49, 0x46, 0x46, 0x00]), "bad.webp", "image/webp");

export const createWebpWithBadChunkSize = () =>
  new MockFile(
    fromHex(
      "52494646" + // RIFF
        "FFFFFFFF" + // riff size huge
        "57454250" + // WEBP
        "56503820" + // VP8  chunk
        "FFFFFFFF" + // chunk size absurd
        "00" // start of data
    ),
    "bad-size.webp",
    "image/webp"
  );
