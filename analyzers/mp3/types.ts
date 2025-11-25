"use strict";

export interface Id3v2FrameFlagSet {
  [key: string]: boolean | undefined;
  tagAlterPreservation?: boolean;
  fileAlterPreservation?: boolean;
  readOnly?: boolean;
  compression?: boolean;
  encryption?: boolean;
  groupingIdentity?: boolean;
  unsynchronisation?: boolean;
  dataLengthIndicator?: boolean;
}

export interface Id3v2FrameDetail {
  id?: string;
  type?: string;
  value?: unknown;
  url?: string;
  description?: string;
  preview?: string;
}

export interface Id3v2Frame {
  id: string;
  size: number;
  flags: Id3v2FrameFlagSet;
  detail: Id3v2FrameDetail;
}

export interface Id3v2Tag {
  versionMajor: number;
  versionRevision: number;
  flags: {
    unsynchronisation: boolean;
    extendedHeader: boolean;
    experimental: boolean;
    footerPresent: boolean;
  };
  size: number;
  tagTotalSize: number;
  extendedHeaderSize: number;
  frames: Id3v2Frame[];
  hasFooter?: boolean;
}

export interface Id3v1Tag {
  title: string;
  artist: string;
  album: string;
  year: string;
  comment: string;
  trackNumber: number | null;
  genreCode: number;
  genreName: string | null;
}

export interface ApeTag {
  offset: number;
  size: number;
  version: number;
  itemCount: number;
}

export interface Lyrics3Tag {
  version: string;
  offset: number | null;
  sizeEstimate: number | string | null;
}

export interface MpegFrameHeader {
  offset: number;
  rawHeader: number;
  versionBits: number;
  versionLabel: string | null;
  layerBits: number;
  layerLabel: string | null;
  hasCrc: boolean;
  bitrateKbps: number | null;
  sampleRate: number | null;
  padding: boolean;
  privateBit: boolean;
  channelModeBits: number;
  channelMode: string | null;
  modeExtension: string | null;
  copyright: boolean;
  original: boolean;
  emphasis: string | null;
  frameLengthBytes: number | null;
  samplesPerFrame: number | null;
}

export interface VbrHeader {
  type: string;
  flags: number | null;
  frames: number | null;
  bytes: number | null;
  quality: number | null;
  lameEncoder: string | null;
  vbrDetected: boolean;
}

export interface Mp3Summary {
  hasId3v2: boolean;
  hasId3v1: boolean;
  hasApeTag: boolean;
  hasLyrics3: boolean;
  audioDataOffset: number;
  durationSeconds: number | null;
  bitrateKbps: number | null;
  channelMode: string | null;
  sampleRateHz: number | null;
  mpegVersion: string | null;
  layer: string | null;
  isVbr: boolean;
  warnings: string[];
}

export interface Mp3SuccessResult {
  isMp3: true;
  mimeGuess: "audio/mpeg";
  summary: Mp3Summary;
  id3v2: Id3v2Tag | null;
  id3v1: Id3v1Tag | null;
  apeTag: ApeTag | null;
  lyrics3: Lyrics3Tag | null;
  mpeg: {
    firstFrame: MpegFrameHeader;
    secondFrameValidated: boolean;
    nonAudioBytes: number;
  };
  vbr: VbrHeader | null;
  durationSeconds: number | null;
  bitrateKbps: number | null;
  audioDataBytes: number;
  warnings: string[];
}

export interface Mp3FailureResult {
  isMp3: false;
  mimeGuess: null;
  reason: string;
  id3v2: Id3v2Tag | null;
  id3v1: Id3v1Tag | null;
  apeTag: ApeTag | null;
  lyrics3: Lyrics3Tag | null;
  mpeg?: undefined;
  vbr?: null;
  durationSeconds?: null;
  bitrateKbps?: null;
  audioDataBytes?: number | null;
  summary?: undefined;
  warnings: string[];
}

export type Mp3ParseResult = Mp3SuccessResult | Mp3FailureResult;
