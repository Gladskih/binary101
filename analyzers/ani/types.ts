"use strict";

import type { RiffParseResult } from "../riff/types.js";
import type { RiffInfoTag } from "../riff/info-tags.js";

export interface AniHeader {
  frameCount: number | null;
  stepCount: number | null;
  width: number | null;
  height: number | null;
  bitCount: number | null;
  planes: number | null;
  jifRate: number | null;
  defaultFps: number | null;
  flags: number | null;
  flagNotes: string[];
}

export interface AniParseResult {
  riff: RiffParseResult;
  header: AniHeader | null;
  rates: number[];
  sequence: number[];
  frames: number;
  infoTags: RiffInfoTag[];
  issues: string[];
}
