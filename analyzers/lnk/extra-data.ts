"use strict";

import { nameForExtraBlock, parseExtraBlock } from "./extra-blocks.js";
import type { LnkExtraData, LnkExtraDataBlock } from "./types.js";

const parseExtraData = (dv: DataView, offset: number, warnings: string[]): LnkExtraData => {
  const blocks: LnkExtraDataBlock[] = [];
  let cursor = offset;
  let terminatorPresent = false;
  while (cursor + 4 <= dv.byteLength) {
    const size = dv.getUint32(cursor, true);
    if (size === 0) {
      terminatorPresent = true;
      break;
    }
    if (size < 8) {
      warnings.push("Encountered malformed ExtraData block smaller than header size.");
      break;
    }
    const signature = dv.getUint32(cursor + 4, true);
    const blockEnd = cursor + size;
    const clampedEnd = Math.min(blockEnd, dv.byteLength);
    const blockDv = new DataView(dv.buffer, dv.byteOffset + cursor, clampedEnd - cursor);
    const block: LnkExtraDataBlock = {
      size,
      signature,
      name: nameForExtraBlock(signature),
      truncated: blockEnd > dv.byteLength,
      parsed: parseExtraBlock(signature, blockDv, warnings)
    };
    blocks.push(block);
    if (blockEnd > dv.byteLength) break;
    cursor = blockEnd;
  }
  if (!terminatorPresent) {
    warnings.push("ExtraData section is missing the required terminal block.");
  }
  return { blocks, endOffset: cursor };
};

export { parseExtraData };
