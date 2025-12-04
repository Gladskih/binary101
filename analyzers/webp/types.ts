"use strict";

import type { RiffChunk } from "../riff/types.js";

export interface WebpDimensions {
  width: number;
  height: number;
  source: string;
  features?: {
    hasIccProfile: boolean;
    hasAlpha: boolean;
    hasExif: boolean;
    hasXmp: boolean;
    hasAnimation: boolean;
  };
}

export interface WebpAnimationInfo {
  backgroundColor: number;
  loopCount: number;
}

export type WebpChunk = RiffChunk;

export interface WebpChunkStats {
  chunkCount: number;
  parsedBytes: number;
  overlayBytes: number;
}

export interface WebpParseResult {
  size: number;
  riffSizeField: number;
  expectedRiffSize: number;
  format: string | null;
  dimensions: WebpDimensions | null;
  hasAlpha: boolean;
  hasAnimation: boolean;
  hasIccProfile: boolean;
  hasExif: boolean;
  hasXmp: boolean;
  animationInfo: WebpAnimationInfo | null;
  frameCount: number;
  chunks: WebpChunk[];
  chunkStats: WebpChunkStats;
  issues: string[];
}

