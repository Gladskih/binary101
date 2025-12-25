"use strict";

export type MpegPsStreamKind = "video" | "audio" | "private" | "padding" | "other";

export type MpegPsPtsStats = {
  count: number;
  first: number | null;
  last: number | null;
  min: number | null;
  max: number | null;
  backwardsCount: number;
  durationSeconds: number | null;
};

export type MpegPsStreamSummary = {
  streamId: number;
  kind: MpegPsStreamKind;
  packetCount: number;
  packetLengthZeroCount: number;
  declaredBytesTotal: number;
  pts: MpegPsPtsStats;
  dtsCount: number;
};

export type MpegPsScrStats = {
  count: number;
  firstSeconds: number | null;
  lastSeconds: number | null;
  minSeconds: number | null;
  maxSeconds: number | null;
  backwardsCount: number;
};

export type MpegPsMuxRateStats = {
  min: number | null;
  max: number | null;
};

export type MpegPsPackHeaderSummary = {
  totalCount: number;
  mpeg1Count: number;
  mpeg2Count: number;
  invalidCount: number;
  stuffingBytesTotal: number;
  scr: MpegPsScrStats;
  muxRate: MpegPsMuxRateStats;
};

export type MpegPsSystemHeaderStreamBound = {
  streamId: number;
  scale: number | null;
  sizeBound: number | null;
  bufferSizeBytes: number | null;
};

export type MpegPsSystemHeaderDetail = {
  headerLength: number;
  rateBound: number | null;
  audioBound: number | null;
  videoBound: number | null;
  fixedFlag: boolean | null;
  cspsFlag: boolean | null;
  systemAudioLockFlag: boolean | null;
  systemVideoLockFlag: boolean | null;
  packetRateRestrictionFlag: boolean | null;
  streamBounds: MpegPsSystemHeaderStreamBound[];
};

export type MpegPsSystemHeaderSummary = {
  totalCount: number;
  truncatedCount: number;
  lengthTotal: number;
  lengthMin: number | null;
  lengthMax: number | null;
  firstHeader: MpegPsSystemHeaderDetail | null;
};

export type MpegPsProgramStreamMapEntry = {
  streamType: number;
  elementaryStreamId: number;
  elementaryStreamInfoLength: number;
};

export type MpegPsProgramStreamMapDetail = {
  length: number;
  currentNextIndicator: boolean | null;
  version: number | null;
  programStreamInfoLength: number | null;
  elementaryStreamMapLength: number | null;
  entries: MpegPsProgramStreamMapEntry[];
  crc32: number | null;
};

export type MpegPsProgramStreamMapSummary = {
  totalCount: number;
  truncatedCount: number;
  firstMap: MpegPsProgramStreamMapDetail | null;
  streamTypes: Array<{ streamType: number; count: number }>;
};

export type MpegPsPesSummary = {
  totalPackets: number;
  totalDeclaredBytes: number;
  streams: MpegPsStreamSummary[];
};

export type MpegPsParseResult = {
  isMpegProgramStream: true;
  fileSize: number;
  packHeaders: MpegPsPackHeaderSummary;
  systemHeaders: MpegPsSystemHeaderSummary;
  programStreamMaps: MpegPsProgramStreamMapSummary;
  pes: MpegPsPesSummary;
  programEndCodeOffset: number | null;
  issues: string[];
};

