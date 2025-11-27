"use strict";

import { MockFile } from "../helpers/mock-file.js";

const fromHex = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex.replace(/\s+/g, ""), "hex"));

// PNG with bad signature
export const createInvalidPngSignature = () =>
  new MockFile(new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00]), "bad.png", "image/png");

// PNG with invalid IHDR length and missing IEND
export const createPngMissingIend = () =>
  new MockFile(
    fromHex(
      "89504E470D0A1A0A" + // signature
        "0000000C" + // IHDR length (wrong, should be 13)
        "49484452" + // IHDR
        "00000001" + // width
        "00000001" + // height
        "08" + // bit depth
        "06" + // color type
        "00" + // compression
        "00" + // filter
        "00" + // interlace
        "00000000" // fake CRC
    ),
    "no-iend.png",
    "image/png"
  );

// PNG with truncated chunk
export const createTruncatedPngChunk = () =>
  new MockFile(
    fromHex(
      "89504E470D0A1A0A" +
        "0000000D4948445200000001000000010806000000" + // valid IHDR (CRC omitted)
        "00000004" + // length
        "49444154" + // IDAT
        "FF" // partial data, missing CRC and rest
    ),
    "truncated.png",
    "image/png"
  );
