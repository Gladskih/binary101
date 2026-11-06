import type { SwfParseResult } from "../analyzers/swf/types.js";

export interface SwfBodyJob {
  file: File;
  start: number;
  end: number;
  swf: SwfParseResult;
}

export type SwfBodyResponse = { analysis: SwfParseResult } | { error: string };
