"use strict";

import { MockFile } from "../helpers/mock-file.js";

const fromHex = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex.replace(/\s+/g, ""), "hex"));

export const createPngWithManyChunks = () =>
  new MockFile(
    fromHex(
      "89504E470D0A1A0A" +
        "0000000D4948445200000001000000010802000000907753DE" + // IHDR
        "00000003624B474400FF00FFA0BDA793" + // bKGD
        "0000000A7048597300000B1300000B1301009A9C1800" + // pHYs
        "0000000B74455874536F6D654B657900" + // tEXt key=SomeKey (truncated value)
        "00000000" // IEND missing
    ),
    "many-chunks.png",
    "image/png"
  );
