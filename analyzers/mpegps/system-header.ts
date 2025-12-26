"use strict";

import type { MpegPsSystemHeaderDetail } from "./types.js";

export const parseSystemHeader = (
  payload: Uint8Array,
  pushIssue: (message: string) => void
): MpegPsSystemHeaderDetail => {
  const headerLength = payload.length;
  if (payload.length < 6) {
    pushIssue("System header payload is too small to read fixed fields.");
    return {
      headerLength,
      rateBound: null,
      audioBound: null,
      videoBound: null,
      fixedFlag: null,
      cspsFlag: null,
      systemAudioLockFlag: null,
      systemVideoLockFlag: null,
      packetRateRestrictionFlag: null,
      streamBounds: []
    };
  }

  const p0 = payload[0] ?? 0;
  const p1 = payload[1] ?? 0;
  const p2 = payload[2] ?? 0;
  const p3 = payload[3] ?? 0;
  const p4 = payload[4] ?? 0;
  const p5 = payload[5] ?? 0;

  const markerOk =
    (p0 & 0x80) !== 0 &&
    (p2 & 0x01) !== 0 &&
    (p4 & 0x20) !== 0 &&
    (p5 & 0x7f) === 0x7f;
  if (!markerOk) pushIssue("System header marker bits or reserved bits look unusual.");

  const rateBound = ((p0 & 0x7f) << 15) | (p1 << 7) | ((p2 & 0xfe) >>> 1);
  const audioBound = (p3 & 0xfc) >>> 2;
  const fixedFlag = (p3 & 0x02) !== 0;
  const cspsFlag = (p3 & 0x01) !== 0;
  const systemAudioLockFlag = (p4 & 0x80) !== 0;
  const systemVideoLockFlag = (p4 & 0x40) !== 0;
  const videoBound = p4 & 0x1f;
  const packetRateRestrictionFlag = (p5 & 0x80) !== 0;

  const streamBounds: Array<{
    streamId: number;
    scale: number | null;
    sizeBound: number | null;
    bufferSizeBytes: number | null;
  }> = [];
  const remainder = payload.length - 6;
  if (remainder % 3 !== 0) {
    pushIssue(`System header stream bounds length is not a multiple of 3 bytes (${remainder}).`);
  }
  for (let offset = 6; offset + 3 <= payload.length; offset += 3) {
    const streamId = payload[offset] ?? 0;
    const b1 = payload[offset + 1] ?? 0;
    const b2 = payload[offset + 2] ?? 0;
    if ((b1 & 0xc0) !== 0xc0) {
      streamBounds.push({ streamId, scale: null, sizeBound: null, bufferSizeBytes: null });
      continue;
    }
    const scale = (b1 & 0x20) !== 0 ? 1 : 0;
    const sizeBound = ((b1 & 0x1f) << 8) | b2;
    const bufferSizeBytes = sizeBound * (scale ? 1024 : 128);
    streamBounds.push({ streamId, scale, sizeBound, bufferSizeBytes });
  }

  return {
    headerLength,
    rateBound,
    audioBound,
    videoBound,
    fixedFlag,
    cspsFlag,
    systemAudioLockFlag,
    systemVideoLockFlag,
    packetRateRestrictionFlag,
    streamBounds
  };
};

