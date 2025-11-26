"use strict";

import {
  type SevenZipContext,
  type SevenZipDigestsInfo,
  type SevenZipPackInfo
} from "./types.js";
import { readBoolVector, readByte, readEncodedUint64, readUint32Le, toSafeNumber } from "./readers.js";

export const parsePackDigests = (
  ctx: SevenZipContext,
  count: number,
  endOffset: number,
  label: string
): SevenZipDigestsInfo => {
  const digests = [] as SevenZipDigestsInfo["digests"];
  const definedFlags = readBoolVector(ctx, count, endOffset, `${label} definition flags`);
  if (!definedFlags) return { digests };
  for (let i = 0; i < count; i += 1) {
    if (!definedFlags[i]) continue;
    const crc = readUint32Le(ctx, endOffset, `${label} CRC`);
    if (crc == null) break;
    digests.push({ index: i, crc });
  }
  return { digests, allDefined: definedFlags.every(Boolean), definedFlags };
};

export const parsePackInfo = (ctx: SevenZipContext): SevenZipPackInfo => {
  const packPos = readEncodedUint64(ctx, "Pack position");
  const numPackStreams = readEncodedUint64(ctx, "Pack stream count");
  const result: SevenZipPackInfo = {
    packPos,
    numPackStreams,
    packSizes: [],
    packCrcs: []
  };
  const countNumber = toSafeNumber(numPackStreams);
  if (packPos == null || numPackStreams == null || countNumber == null) return result;
  let done = false;
  while (ctx.offset < ctx.dv.byteLength && !done) {
    const id = readByte(ctx, "Pack info field id");
    if (id == null) break;
    if (id === 0x00) {
      done = true;
      break;
    }
    if (id === 0x09) {
      for (let i = 0; i < countNumber; i += 1) {
        const size = readEncodedUint64(ctx, "Pack stream size");
        if (size == null) break;
        result.packSizes.push(size);
      }
      continue;
    }
    if (id === 0x0a) {
      const digestInfo = parsePackDigests(
        ctx,
        countNumber,
        ctx.dv.byteLength,
        "Pack stream"
      );
      result.packCrcs = digestInfo.digests;
      continue;
    }
    ctx.issues.push(`Unknown PackInfo field id 0x${id.toString(16)}.`);
    break;
  }
  return result;
};
