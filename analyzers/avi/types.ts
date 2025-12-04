"use strict";

import type { RiffParseResult } from "../riff/types.js";
import type { RiffInfoTag } from "../riff/info-tags.js";
import type { WaveFormatInfo } from "../riff/wave-format.js";

export interface AviMainHeader {
  microSecPerFrame: number | null;
  frameRate: number | null;
  maxBytesPerSec: number | null;
  totalFrames: number | null;
  streams: number | null;
  width: number | null;
  height: number | null;
  suggestedBufferSize: number | null;
  flags: number | null;
  durationSeconds: number | null;
}

export interface AviRect {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

export interface AviStreamHeader {
  type: string | null;
  handler: string | null;
  flags: number | null;
  initialFrames: number | null;
  scale: number | null;
  rate: number | null;
  start: number | null;
  length: number | null;
  suggestedBufferSize: number | null;
  quality: number | null;
  sampleSize: number | null;
  frame: AviRect | null;
}

export interface AviVideoFormat {
  width: number | null;
  height: number | null;
  bitCount: number | null;
  compression: string | null;
  sizeImage: number | null;
}

export interface AviStream {
  index: number;
  header: AviStreamHeader | null;
  format: WaveFormatInfo | AviVideoFormat | null;
  name: string | null;
  issues: string[];
}

export interface AviParseResult {
  riff: RiffParseResult;
  mainHeader: AviMainHeader | null;
  streams: AviStream[];
  infoTags: RiffInfoTag[];
  issues: string[];
}
