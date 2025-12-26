"use strict";

import type { MpegPsProgramStreamMapDetail } from "./types.js";

const readUint16be = (bytes: Uint8Array, offset: number): number =>
  ((bytes[offset] ?? 0) << 8) | (bytes[offset + 1] ?? 0);

export const parseProgramStreamMap = (
  payload: Uint8Array,
  pushIssue: (message: string) => void
): MpegPsProgramStreamMapDetail => {
  const length = payload.length;
  if (payload.length < 10) {
    pushIssue("Program Stream Map is too small to parse.");
    return {
      length,
      currentNextIndicator: null,
      version: null,
      programStreamInfoLength: null,
      elementaryStreamMapLength: null,
      entries: [],
      crc32: null
    };
  }

  const first = payload[0] ?? 0;
  const second = payload[1] ?? 0;
  const currentNextIndicator = (first & 0x80) !== 0;
  const version = first & 0x1f;
  const markerOk = (second & 0x01) !== 0;
  if (!markerOk) pushIssue("Program Stream Map marker bit is not set.");

  let cursor = 2;
  const programStreamInfoLength = readUint16be(payload, cursor);
  cursor += 2;
  cursor += programStreamInfoLength;
  if (cursor + 2 > payload.length) {
    pushIssue("Program Stream Map ended while skipping program_stream_info.");
    return {
      length,
      currentNextIndicator,
      version,
      programStreamInfoLength,
      elementaryStreamMapLength: null,
      entries: [],
      crc32: null
    };
  }
  const elementaryStreamMapLength = readUint16be(payload, cursor);
  cursor += 2;
  const entriesEnd = cursor + elementaryStreamMapLength;
  if (entriesEnd > payload.length) {
    pushIssue("Program Stream Map elementary stream map length exceeds payload.");
  }
  const entries: MpegPsProgramStreamMapDetail["entries"] = [];
  while (cursor + 4 <= payload.length && cursor + 4 <= entriesEnd) {
    const streamType = payload[cursor] ?? 0;
    const elementaryStreamId = payload[cursor + 1] ?? 0;
    const infoLength = readUint16be(payload, cursor + 2);
    cursor += 4;
    cursor += infoLength;
    entries.push({
      streamType,
      elementaryStreamId,
      elementaryStreamInfoLength: infoLength
    });
  }

  const crcOffset = payload.length - 4;
  const crc32 =
    crcOffset >= 0 && crcOffset + 4 <= payload.length
      ? (((payload[crcOffset] ?? 0) << 24) |
          ((payload[crcOffset + 1] ?? 0) << 16) |
          ((payload[crcOffset + 2] ?? 0) << 8) |
          (payload[crcOffset + 3] ?? 0)) >>> 0
      : null;

  return {
    length,
    currentNextIndicator,
    version,
    programStreamInfoLength,
    elementaryStreamMapLength,
    entries,
    crc32
  };
};

