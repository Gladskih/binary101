"use strict";

import { MockFile } from "../helpers/mock-file.mjs";

const fromHex = hex => new Uint8Array(Buffer.from(hex.replace(/\s+/g, ""), "hex"));

export const createGifWithBadTrailer = () =>
  new MockFile(
    fromHex(
      "47494638396101000100000000" + // GIF89a header width/height
        "0000" + // background/pixel aspect
        "2c0000000001000100000202440100" + // minimal image + sub-blocks
        "00" // missing trailer 0x3b
    ),
    "bad-trailer.gif",
    "image/gif"
  );

export const createGifWithTruncatedExtension = () =>
  new MockFile(
    fromHex(
      "47494638396101000100000000" +
        "2101" + // plain text extension with no data
        "00" // immediate terminator + trailer missing
    ),
    "truncated-ext.gif",
    "image/gif"
  );
