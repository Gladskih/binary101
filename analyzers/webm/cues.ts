"use strict";

import {
  CUE_BLOCK_NUMBER_ID,
  CUE_CLUSTER_POSITION_ID,
  CUE_POINT_ID,
  CUE_RELATIVE_POSITION_ID,
  CUE_TIME_ID,
  CUE_TRACK_ID,
  CUE_TRACK_POSITIONS_ID,
  MAX_CUES_BYTES
} from "./constants.js";
import { clampReadLength, readElementHeader, readUnsigned } from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues, WebmCues, WebmCuePoint, WebmCueTrackPosition } from "./types.js";

const parseCueTrackPosition = (
  dv: DataView,
  offset: number,
  size: number,
  absoluteOffset: number,
  issues: Issues
): WebmCueTrackPosition => {
  const position: WebmCueTrackPosition = {
    track: null,
    clusterPosition: null,
    relativePosition: null,
    blockNumber: null
  };
  let cursor = 0;
  const limit = Math.min(size, dv.byteLength - offset);
  while (cursor < limit) {
    const header = readElementHeader(dv, offset + cursor, absoluteOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    const dataStart = offset + cursor + header.headerSize;
    const available = Math.min(header.size ?? 0, limit - (cursor + header.headerSize));
    if (header.id === CUE_TRACK_ID && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "CueTrack");
      if (value != null && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
        position.track = Number(value);
      }
    } else if (header.id === CUE_CLUSTER_POSITION_ID && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "CueClusterPosition");
      if (value != null && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
        position.clusterPosition = Number(value);
      }
    } else if (header.id === CUE_RELATIVE_POSITION_ID && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "CueRelativePosition");
      if (value != null && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
        position.relativePosition = Number(value);
      }
    } else if (header.id === CUE_BLOCK_NUMBER_ID && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "CueBlockNumber");
      if (value != null && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
        position.blockNumber = Number(value);
      }
    }
    if (header.size == null) break;
    cursor += header.headerSize + header.size;
  }
  return position;
};

const parseCuePoint = (
  dv: DataView,
  offset: number,
  size: number,
  absoluteOffset: number,
  issues: Issues,
  timecodeScale: number | null
): WebmCuePoint => {
  let timecode: number | null = null;
  const positions: WebmCueTrackPosition[] = [];
  let cursor = 0;
  const limit = Math.min(size, dv.byteLength - offset);
  while (cursor < limit) {
    const header = readElementHeader(dv, offset + cursor, absoluteOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    const dataStart = offset + cursor + header.headerSize;
    const available = Math.min(header.size ?? 0, limit - (cursor + header.headerSize));
    if (header.id === CUE_TIME_ID && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "CueTime");
      if (value != null && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
        timecode = Number(value);
      } else if (value != null) {
        issues.push("CueTime exceeds safe integer range.");
      }
    } else if (header.id === CUE_TRACK_POSITIONS_ID && header.size != null) {
      const position = parseCueTrackPosition(
        dv,
        dataStart,
        Math.min(header.size, available),
        absoluteOffset + cursor,
        issues
      );
      positions.push(position);
    }
    if (header.size == null) break;
    cursor += header.headerSize + header.size;
  }
  const timecodeSeconds =
    timecode != null && timecodeScale != null ? (timecode * timecodeScale) / 1e9 : null;
  return { timecode, timecodeSeconds, positions };
};

export const parseCues = async (
  file: File,
  cuesHeader: EbmlElementHeader,
  issues: Issues,
  timecodeScale: number | null
): Promise<WebmCues> => {
  const { length, truncated } = clampReadLength(file.size, cuesHeader.dataOffset, cuesHeader.size, MAX_CUES_BYTES);
  const dv = new DataView(await file.slice(cuesHeader.dataOffset, cuesHeader.dataOffset + length).arrayBuffer());
  const limit = cuesHeader.size != null ? Math.min(cuesHeader.size, dv.byteLength) : dv.byteLength;
  const cuePoints: WebmCuePoint[] = [];
  let cursor = 0;
  while (cursor < limit) {
    const header = readElementHeader(dv, cursor, cuesHeader.dataOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    if (header.id === CUE_POINT_ID && header.size != null) {
      const dataStart = cursor + header.headerSize;
      const available = Math.min(header.size, limit - dataStart);
      const cuePoint = parseCuePoint(
        dv,
        dataStart,
        available,
        cuesHeader.dataOffset + dataStart,
        issues,
        timecodeScale
      );
      cuePoints.push(cuePoint);
    }
    if (header.size == null) break;
    cursor += header.headerSize + (header.size ?? 0);
  }
  return { cuePoints, truncated: truncated || (cuesHeader.size != null && length < cuesHeader.size) };
};
