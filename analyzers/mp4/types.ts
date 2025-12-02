"use strict";

export interface Mp4BoxSummary {
  type: string;
  start: number;
  end: number;
  size: number;
  headerSize: number;
  largesize?: number | null;
  truncated?: boolean;
}

export interface Mp4BrandInfo {
  majorBrand: string | null;
  minorVersion: number | null;
  compatibleBrands: string[];
}

export interface Mp4MovieHeader {
  creationTime: string | null;
  modificationTime: string | null;
  timescale: number | null;
  duration: number | null;
  durationSeconds: number | null;
  rate: number | null;
  volume: number | null;
  nextTrackId: number | null;
}

export type Mp4TrackKind = "video" | "audio" | "hint" | "text" | "meta" | "subtitles" | "unknown";

export interface Mp4CodecAvc {
  profileIdc: number | null;
  profileCompatibility: number | null;
  levelIdc: number | null;
}

export interface Mp4CodecHevc {
  profileIdc: number | null;
  tierFlag: number | null;
  levelIdc: number | null;
}

export interface Mp4CodecAv1 {
  profile: number | null;
  level: number | null;
  bitDepth: number | null;
}

export interface Mp4CodecVp9 {
  profile: number | null;
  level: number | null;
  bitDepth: number | null;
}

export interface Mp4CodecAac {
  audioObjectType: number | null;
  samplingFrequencyIndex: number | null;
  channelConfiguration: number | null;
}

export interface Mp4CodecDetails {
  format: string;
  codecString: string | null;
  profile: string | null;
  level: string | null;
  description: string | null;
  width: number | null;
  height: number | null;
  pixelAspectRatio: string | null;
  channels: number | null;
  sampleRate: number | null;
  bitDepth: number | null;
  bitrate: number | null;
  avc?: Mp4CodecAvc;
  hevc?: Mp4CodecHevc;
  av1?: Mp4CodecAv1;
  vp9?: Mp4CodecVp9;
  aac?: Mp4CodecAac;
}

export interface Mp4Track {
  id: number | null;
  kind: Mp4TrackKind;
  handlerType: string | null;
  handlerName: string | null;
  creationTime: string | null;
  modificationTime: string | null;
  duration: number | null;
  durationSeconds: number | null;
  timescale: number | null;
  language: string | null;
  width: number | null;
  height: number | null;
  volume: number | null;
  sampleCount: number | null;
  keyframeCount: number | null;
  chunkCount: number | null;
  sampleSizeConstant: number | null;
  codec: Mp4CodecDetails | null;
  warnings: string[];
}

export interface Mp4ParseResult {
  isMp4: boolean;
  brands: Mp4BrandInfo | null;
  movieHeader: Mp4MovieHeader | null;
  tracks: Mp4Track[];
  fragmentCount: number;
  mdatBytes: number;
  fastStart: boolean | null;
  topLevelBoxes: Mp4BoxSummary[];
  warnings: string[];
}
