"use strict";

import { escapeHtml } from "../../html-utils.js";
import { renderApe, renderId3v1, renderId3v2, renderLyrics } from "./tags-section.js";
import { renderMpeg } from "./mpeg-section.js";
import { renderSummary } from "./summary-section.js";
import { renderVbr } from "./vbr-section.js";
import { renderWarnings } from "./warnings.js";

export function renderMp3(mp3) {
  if (!mp3) return "";
  const out = [];
  out.push("<h3>MPEG audio (MP3)</h3>");
  if (!mp3.isMp3) {
    out.push(`<p>Not detected as MP3: ${escapeHtml(mp3.reason || "Unknown reason")}</p>`);
    out.push(renderWarnings(mp3.warnings));
    return out.join("");
  }
  out.push(renderSummary(mp3));
  out.push(renderMpeg(mp3.mpeg));
  out.push(renderVbr(mp3.vbr));
  out.push(renderId3v2(mp3.id3v2));
  out.push(renderId3v1(mp3.id3v1));
  out.push(renderApe(mp3.apeTag));
  out.push(renderLyrics(mp3.lyrics3));
  out.push(renderWarnings(mp3.warnings));
  return out.join("");
}
