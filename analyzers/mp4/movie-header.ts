"use strict";

import { parseCreationTime, readFixed1616, readFixed88 } from "./boxes.js";
import type { Mp4MovieHeader } from "./types.js";

export const parseMvhd = (view: DataView, start: number, size: number, issues: string[]): Mp4MovieHeader | null => {
  if (size < 24) {
    issues.push("mvhd box truncated.");
    return null;
  }
  const version = view.getUint8(start);
  let offset = start + 4;
  let creation: number | null = null;
  let modification: number | null = null;
  let timescale: number | null = null;
  let duration: number | null = null;
  if (version === 1) {
    if (offset + 28 > start + size) {
      issues.push("mvhd version 1 box truncated.");
      return null;
    }
    creation = Number(view.getBigUint64(offset, false));
    modification = Number(view.getBigUint64(offset + 8, false));
    timescale = view.getUint32(offset + 16, false);
    duration = Number(view.getBigUint64(offset + 20, false));
    offset += 28;
  } else {
    if (offset + 16 > start + size) {
      issues.push("mvhd version 0 box truncated.");
      return null;
    }
    creation = view.getUint32(offset, false);
    modification = view.getUint32(offset + 4, false);
    timescale = view.getUint32(offset + 8, false);
    duration = view.getUint32(offset + 12, false);
    offset += 16;
  }
  const rate = readFixed1616(view.getUint32(offset, false));
  const volume = readFixed88(view.getUint16(offset + 4, false));
  const nextTrackIdOffset = start + size - 4;
  const nextTrackId = nextTrackIdOffset >= start ? view.getUint32(nextTrackIdOffset, false) : null;
  const durationSeconds = timescale && duration != null ? duration / timescale : null;
  return {
    creationTime: parseCreationTime(creation),
    modificationTime: parseCreationTime(modification),
    timescale: timescale ?? null,
    duration,
    durationSeconds,
    rate,
    volume,
    nextTrackId
  };
};
