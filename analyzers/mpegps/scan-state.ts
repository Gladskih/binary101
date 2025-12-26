"use strict";

import type {
  MpegPsPackHeaderSummary,
  MpegPsParseResult,
  MpegPsProgramStreamMapDetail,
  MpegPsProgramStreamMapSummary,
  MpegPsStreamKind,
  MpegPsStreamSummary,
  MpegPsSystemHeaderDetail,
  MpegPsSystemHeaderSummary
} from "./types.js";

export type MutablePts = {
  count: number;
  first: number | null;
  last: number | null;
  min: number | null;
  max: number | null;
  lastSeen: number | null;
  backwardsCount: number;
};

export type MutableStream = {
  streamId: number;
  kind: MpegPsStreamKind;
  packetCount: number;
  packetLengthZeroCount: number;
  declaredBytesTotal: number;
  pts: MutablePts;
  dtsCount: number;
};

export type MpegPsScanState = {
  packHeaders: MpegPsPackHeaderSummary;
  systemHeaders: MpegPsSystemHeaderSummary;
  programStreamMaps: MpegPsProgramStreamMapSummary;
  programStreamMapTypeCounts: Map<number, number>;
  streamStats: Map<number, MutableStream>;
  pesTotalPackets: number;
  pesTotalDeclaredBytes: number;
  programEndCodeOffset: number | null;
};

const createEmptyPts = (): MutablePts => ({
  count: 0,
  first: null,
  last: null,
  min: null,
  max: null,
  lastSeen: null,
  backwardsCount: 0
});

const classifyStreamId = (streamId: number): MpegPsStreamKind => {
  if (streamId >= 0xe0 && streamId <= 0xef) return "video";
  if (streamId >= 0xc0 && streamId <= 0xdf) return "audio";
  if (streamId === 0xbd || streamId === 0xbf) return "private";
  if (streamId === 0xbe) return "padding";
  return "other";
};

export const createMpegPsScanState = (): MpegPsScanState => {
  const packHeaders: MpegPsPackHeaderSummary = {
    totalCount: 0,
    mpeg1Count: 0,
    mpeg2Count: 0,
    invalidCount: 0,
    stuffingBytesTotal: 0,
    scr: {
      count: 0,
      firstSeconds: null,
      lastSeconds: null,
      minSeconds: null,
      maxSeconds: null,
      backwardsCount: 0
    },
    muxRate: { min: null, max: null }
  };

  const systemHeaders: MpegPsSystemHeaderSummary = {
    totalCount: 0,
    truncatedCount: 0,
    lengthTotal: 0,
    lengthMin: null,
    lengthMax: null,
    firstHeader: null as MpegPsSystemHeaderDetail | null
  };

  const programStreamMaps: MpegPsProgramStreamMapSummary = {
    totalCount: 0,
    truncatedCount: 0,
    firstMap: null as MpegPsProgramStreamMapDetail | null,
    streamTypes: []
  };

  return {
    packHeaders,
    systemHeaders,
    programStreamMaps,
    programStreamMapTypeCounts: new Map(),
    streamStats: new Map(),
    pesTotalPackets: 0,
    pesTotalDeclaredBytes: 0,
    programEndCodeOffset: null
  };
};

export const getOrCreateStream = (state: MpegPsScanState, streamId: number): MutableStream => {
  const existing = state.streamStats.get(streamId);
  if (existing) return existing;
  const created: MutableStream = {
    streamId,
    kind: classifyStreamId(streamId),
    packetCount: 0,
    packetLengthZeroCount: 0,
    declaredBytesTotal: 0,
    pts: createEmptyPts(),
    dtsCount: 0
  };
  state.streamStats.set(streamId, created);
  return created;
};

const buildStreamSummary = (stream: MutableStream): MpegPsStreamSummary => {
  const durationSeconds =
    stream.pts.count >= 2 &&
    stream.pts.backwardsCount === 0 &&
    stream.pts.first != null &&
    stream.pts.last != null &&
    stream.pts.last >= stream.pts.first
      ? (stream.pts.last - stream.pts.first) / 90000
      : null;

  return {
    streamId: stream.streamId,
    kind: stream.kind,
    packetCount: stream.packetCount,
    packetLengthZeroCount: stream.packetLengthZeroCount,
    declaredBytesTotal: stream.declaredBytesTotal,
    pts: {
      count: stream.pts.count,
      first: stream.pts.first,
      last: stream.pts.last,
      min: stream.pts.min,
      max: stream.pts.max,
      backwardsCount: stream.pts.backwardsCount,
      durationSeconds: durationSeconds != null ? Math.round(durationSeconds * 1000) / 1000 : null
    },
    dtsCount: stream.dtsCount
  };
};

export const finalizeMpegPsScanResult = (
  fileSize: number,
  state: MpegPsScanState,
  issues: string[]
): MpegPsParseResult => {
  const streams = Array.from(state.streamStats.values())
    .sort((a, b) => a.streamId - b.streamId)
    .map(buildStreamSummary);

  const streamTypes = Array.from(state.programStreamMapTypeCounts.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([streamType, count]) => ({ streamType, count }));

  const programStreamMaps: MpegPsProgramStreamMapSummary = {
    ...state.programStreamMaps,
    streamTypes
  };

  return {
    isMpegProgramStream: true,
    fileSize,
    packHeaders: state.packHeaders,
    systemHeaders: state.systemHeaders,
    programStreamMaps,
    pes: {
      totalPackets: state.pesTotalPackets,
      totalDeclaredBytes: state.pesTotalDeclaredBytes,
      streams
    },
    programEndCodeOffset: state.programEndCodeOffset,
    issues
  };
};

