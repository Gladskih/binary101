"use strict";

import {
  type SevenZipContext,
  type SevenZipStreamsInfo,
  type SevenZipSubStreamsInfo
} from "./types.js";
import { parsePackDigests, parsePackInfo } from "./pack-info.js";
import { parseUnpackInfo } from "./unpack-info.js";
import { readByte, readEncodedUint64, toSafeNumber } from "./readers.js";

export const parseSubStreamsInfo = (
  ctx: SevenZipContext,
  folderCount: number
): SevenZipSubStreamsInfo => {
  const info: SevenZipSubStreamsInfo = { numUnpackStreams: new Array(folderCount).fill(1) };
  let done = false;
  while (ctx.offset < ctx.dv.byteLength && !done) {
    const id = readByte(ctx, "SubStreamsInfo field id");
    if (id == null) break;
    if (id === 0x00) {
      done = true;
      break;
    }
    if (id === 0x0d) {
      info.numUnpackStreams = [];
      for (let i = 0; i < folderCount; i += 1) {
        const value = readEncodedUint64(ctx, "Unpack stream count");
        info.numUnpackStreams.push(value);
      }
      continue;
    }
    if (id === 0x09) {
      info.substreamSizes = [];
      const totalEntries = info.numUnpackStreams.reduce<number>((sum, value) => {
        const count = toSafeNumber(value) ?? 1;
        return sum + Math.max(count - 1, 0);
      }, 0);
      for (let i = 0; i < totalEntries; i += 1) {
        const size = readEncodedUint64(ctx, "Substream size");
        info.substreamSizes.push(size);
      }
      continue;
    }
    if (id === 0x0a) {
      const totalStreams = info.numUnpackStreams.reduce<number>((sum, value) => {
        const count = toSafeNumber(value) ?? 1;
        return sum + count;
      }, 0);
      const digestInfo = parsePackDigests(
        ctx,
        totalStreams,
        ctx.dv.byteLength,
        "Substream"
      );
      info.substreamCrcs = digestInfo;
      continue;
    }
    ctx.issues.push(`Unknown SubStreamsInfo field id 0x${id.toString(16)}.`);
    break;
  }
  return info;
};

export const parseStreamsInfo = (ctx: SevenZipContext): SevenZipStreamsInfo => {
  const info: SevenZipStreamsInfo = {};
  let done = false;
  while (ctx.offset < ctx.dv.byteLength && !done) {
    const id = readByte(ctx, "StreamsInfo field id");
    if (id == null) break;
    if (id === 0x00) {
      done = true;
      break;
    }
    if (id === 0x06) {
      info.packInfo = parsePackInfo(ctx);
      continue;
    }
    if (id === 0x07) {
      info.unpackInfo = parseUnpackInfo(ctx);
      continue;
    }
    if (id === 0x08) {
      const folderCount =
        toSafeNumber(info.unpackInfo?.folders?.length || 0) || 0;
      info.subStreamsInfo = parseSubStreamsInfo(ctx, folderCount);
      continue;
    }
    ctx.issues.push(`Unknown StreamsInfo field id 0x${id.toString(16)}.`);
    break;
  }
  return info;
};
