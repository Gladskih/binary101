"use strict";

import type { RiffParseResult } from "../riff/types.js";
import type { RiffInfoTag } from "../riff/info-tags.js";
import type { WaveFormatInfo } from "../riff/wave-format.js";

export interface WavDataChunk {
  size: number;
  offset: number;
  durationSeconds: number | null;
  truncated: boolean;
}

export interface WavParseResult {
  riff: RiffParseResult;
  format: WaveFormatInfo | null;
  data: WavDataChunk | null;
  factSampleLength: number | null;
  infoTags: RiffInfoTag[];
  issues: string[];
}
