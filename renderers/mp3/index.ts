"use strict";

import { escapeHtml } from "../../html-utils.js";
import { renderApe, renderId3v1, renderId3v2, renderLyrics } from "./tags-section.js";
import { renderMpeg } from "./mpeg-section.js";
import { renderSummary } from "./summary-section.js";
import { renderVbr } from "./vbr-section.js";
import { renderWarnings } from "./warnings.js";
import type { Mp3FailureResult, Mp3ParseResult, Mp3SuccessResult } from "../../analyzers/mp3/types.js";

export function renderMp3(mp3: Mp3ParseResult | null | unknown): string {
  const data = mp3 as Mp3ParseResult | null;
  if (!data) return "";
  const out = [];
  out.push("<h3>MPEG audio (MP3)</h3>");
  if (!data.isMp3) {
    const failure = data as Mp3FailureResult;
    out.push(`<p>Not detected as MP3: ${escapeHtml(failure.reason || "Unknown reason")}</p>`);
    out.push(renderWarnings(failure.warnings));
    return out.join("");
  }
  const success = data as Mp3SuccessResult;
  out.push(renderSummary(success));
  out.push(renderMpeg(success.mpeg));
  out.push(renderVbr(success.vbr || null));
  out.push(renderId3v2(success.id3v2));
  out.push(renderId3v1(success.id3v1));
  out.push(renderApe(success.apeTag));
  out.push(renderLyrics(success.lyrics3));
  out.push(renderWarnings(success.warnings));
  return out.join("");
}
