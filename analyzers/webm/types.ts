"use strict";

export interface WebmEbmlHeader {
  docType: string | null;
  docTypeVersion: number | null;
  docTypeReadVersion: number | null;
  ebmlVersion: number | null;
  ebmlReadVersion: number | null;
  maxIdLength: number | null;
  maxSizeLength: number | null;
}

export interface WebmInfo {
  timecodeScale: number | null;
  duration: number | null;
  durationSeconds: number | null;
  muxingApp: string | null;
  writingApp: string | null;
  title: string | null;
  dateUtc: string | null;
  segmentUid: string | null;
}

export interface WebmTrackVideo {
  pixelWidth: number | null;
  pixelHeight: number | null;
  displayWidth: number | null;
  displayHeight: number | null;
  stereoMode: number | null;
  alphaMode: number | null;
}

export interface WebmTrackAudio {
  samplingFrequency: number | null;
  outputSamplingFrequency: number | null;
  channels: number | null;
  bitDepth: number | null;
}

export interface WebmTrack {
  trackNumber: number | null;
  trackUid: string | number | null;
  trackType: number | null;
  trackTypeLabel: string;
  name: string | null;
  language: string | null;
  codecId: string | null;
  codecName: string | null;
  defaultDuration: number | null;
  defaultDurationFps: number | null;
  codecPrivateSize: number | null;
  flagEnabled: boolean | null;
  flagDefault: boolean | null;
  flagForced: boolean | null;
  flagLacing: boolean | null;
  video: WebmTrackVideo | null;
  audio: WebmTrackAudio | null;
}

export interface WebmSeekEntry {
  id: number;
  name: string;
  position: number | null;
  absoluteOffset: number | null;
}

export interface WebmSeekHead {
  entries: WebmSeekEntry[];
  truncated: boolean;
}

export interface WebmSegment {
  offset: number;
  size: number | null;
  dataOffset: number;
  dataSize: number | null;
  info: WebmInfo | null;
  tracks: WebmTrack[];
  seekHead: WebmSeekHead | null;
  scannedElements: Array<{ id: number; offset: number; size: number | null }>;
  scanLimit: number;
}

export interface WebmParseResult {
  isWebm: boolean;
  isMatroska: boolean;
  docType: string | null;
  ebmlHeader: WebmEbmlHeader;
  segment: WebmSegment | null;
  issues: string[];
}
