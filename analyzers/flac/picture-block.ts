"use strict";

import { decodeAscii, decodeUtf8 } from "./text-reading.js";
import type { FlacPictureBlock } from "./types.js";

const utf8Decoder = new TextDecoder("utf-8", { fatal: false });

const parsePicture = (
  base: FlacPictureBlock,
  data: DataView,
  warnings: string[]
): FlacPictureBlock => {
  let offset = 0;
  const require = (size: number, message: string): boolean => {
    if (offset + size > data.byteLength) {
      warnings.push(message);
      return false;
    }
    return true;
  };
  if (!require(4, "PICTURE block missing picture type.")) return base;
  base.pictureType = data.getUint32(offset, false);
  offset += 4;
  if (!require(4, "PICTURE block missing MIME length.")) return base;
  const mimeLength = data.getUint32(offset, false);
  offset += 4;
  if (mimeLength > 0) {
    const available = Math.max(0, Math.min(mimeLength, data.byteLength - offset));
    if (mimeLength > available) warnings.push("PICTURE MIME string is truncated.");
    base.mimeType = decodeAscii(data, offset, available);
  } else base.mimeType = "";
  offset += mimeLength;
  if (!require(4, "PICTURE block missing description length.")) return base;
  const descLength = data.getUint32(offset, false);
  offset += 4;
  if (descLength > 0) {
    const available = Math.max(0, Math.min(descLength, data.byteLength - offset));
    if (descLength > available) warnings.push("PICTURE description is truncated.");
    base.description = decodeUtf8(data, offset, available, utf8Decoder);
  } else base.description = "";
  offset += descLength;
  if (!require(20, "PICTURE dimensions are truncated.")) return base;
  base.width = data.getUint32(offset, false);
  base.height = data.getUint32(offset + 4, false);
  base.depth = data.getUint32(offset + 8, false);
  base.colors = data.getUint32(offset + 12, false);
  base.dataLength = data.getUint32(offset + 16, false);
  return base;
};

export { parsePicture };
