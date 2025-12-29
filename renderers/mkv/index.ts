"use strict";

import type { WebmParseResult } from "../../analyzers/webm/types.js";
import { renderWebm } from "../webm/index.js";

export function renderMkv(mkv: WebmParseResult | null | unknown): string {
  return renderWebm(mkv);
}

