"use strict";

import { parsePcapNg as parsePcapNgBlocks } from "./parser.js";
import type { PcapNgParseResult } from "./types.js";

export type { PcapNgParseResult } from "./types.js";

export const parsePcapNg = async (file: File): Promise<PcapNgParseResult | null> => {
  const issues: string[] = [];
  const pushIssue = (message: string): void => {
    issues.push(message);
  };

  const parsed = await parsePcapNgBlocks(file, pushIssue);
  return parsed ? { ...parsed, issues } : null;
};
