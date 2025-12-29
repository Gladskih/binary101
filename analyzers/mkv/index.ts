"use strict";

import { parseWebm } from "../webm/index.js";
import type { WebmParseResult } from "../webm/types.js";

export async function parseMkv(file: File): Promise<WebmParseResult | null> {
  const parsed = await parseWebm(file);
  if (!parsed || parsed.isWebm) return null;
  return parsed;
}

