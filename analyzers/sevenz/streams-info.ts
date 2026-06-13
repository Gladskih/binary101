"use strict";

import {
  type SevenZipContext,
  type SevenZipStreamsInfo,
  type SevenZipSubStreamsInfo
} from "./types.js";
import { parsePackDigests, parsePackInfo } from "./pack-info.js";
import { parseUnpackInfo } from "./unpack-info.js";
import { readByte, readEncodedUint64, toSafeNumber } from "./readers.js";

// 7z DOC/7zFormat.txt NID values for StreamsInfo and SubStreamsInfo sections.
// https://www.7-zip.org/sdk.html
const END_ID = 0x00;
const PACK_INFO_ID = 0x06;
const UNPACK_INFO_ID = 0x07;
const SUBSTREAMS_INFO_ID = 0x08;
const SUBSTREAM_SIZES_ID = 0x09;
const SUBSTREAM_CRCS_ID = 0x0a;
const NUM_UNPACK_STREAMS_ID = 0x0d;

const readSafeUnpackStreamCount = (
  ctx: SevenZipContext,
  value: bigint | number | null | undefined
): number | null => {
  const count = toSafeNumber(value);
  if (count == null || count < 0) {
    ctx.issues.push("Unpack stream count exceeds supported range.");
    return null;
  }
  return count;
};

const sumSubstreamSizeEntries = (
  ctx: SevenZipContext,
  values: Array<bigint | number | null | undefined>
): number | null => values.reduce<number | null>((sum, value) => {
  if (sum == null) return null;
  const count = readSafeUnpackStreamCount(ctx, value);
  if (count == null) return null;
  return sum + Math.max(count - 1, 0);
}, 0);

const sumSubstreamCrcEntries = (
  ctx: SevenZipContext,
  values: Array<bigint | number | null | undefined>
): number | null => values.reduce<number | null>((sum, value) => {
  if (sum == null) return null;
  const count = readSafeUnpackStreamCount(ctx, value);
  if (count == null) return null;
  return sum + count;
}, 0);

export const parseSubStreamsInfo = (
  ctx: SevenZipContext,
  folderCount: number
): SevenZipSubStreamsInfo => {
  const info: SevenZipSubStreamsInfo = {
    numUnpackStreams: new Array<number>(folderCount).fill(1)
  };
  while (ctx.offset < ctx.dv.byteLength) {
    const id = readByte(ctx, "SubStreamsInfo field id");
    if (id == null) break;
    if (id === END_ID) break;
    if (id === NUM_UNPACK_STREAMS_ID) {
      info.numUnpackStreams = [];
      for (let i = 0; i < folderCount; i += 1) {
        const value = readEncodedUint64(ctx, "Unpack stream count");
        info.numUnpackStreams.push(value);
      }
      continue;
    }
    if (id === SUBSTREAM_SIZES_ID) {
      info.substreamSizes = [];
      const totalEntries = sumSubstreamSizeEntries(ctx, info.numUnpackStreams);
      if (totalEntries == null) {
        ctx.offset = ctx.dv.byteLength;
        return info;
      }
      for (let i = 0; i < totalEntries; i += 1) {
        const size = readEncodedUint64(ctx, "Substream size");
        info.substreamSizes.push(size);
      }
      continue;
    }
    if (id === SUBSTREAM_CRCS_ID) {
      const totalStreams = sumSubstreamCrcEntries(ctx, info.numUnpackStreams);
      if (totalStreams == null) {
        ctx.offset = ctx.dv.byteLength;
        return info;
      }
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
  while (ctx.offset < ctx.dv.byteLength) {
    const id = readByte(ctx, "StreamsInfo field id");
    if (id == null) break;
    if (id === END_ID) break;
    if (id === PACK_INFO_ID) {
      info.packInfo = parsePackInfo(ctx);
      continue;
    }
    if (id === UNPACK_INFO_ID) {
      info.unpackInfo = parseUnpackInfo(ctx);
      continue;
    }
    if (id === SUBSTREAMS_INFO_ID) {
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
