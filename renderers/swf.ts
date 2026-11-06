import { escapeHtml, renderDefinitionRow } from "../html-utils.js";
import { hex, humanSize } from "../binary-utils.js";
import type { SwfParseResult } from "../analyzers/swf/types.js";

// Adobe SWF v19, Appendix B. Unknown tag codes stay numeric, never guessed.
// https://open-flash.github.io/mirrors/swf-spec-19.pdf
// Additional upstream tag names: https://github.com/ruffle-rs/ruffle/blob/master/swf/src/tag_code.rs
const TAG_NAMES: Readonly<Record<number, string>> = {
  0: "End", 1: "ShowFrame", 9: "SetBackgroundColor", 12: "DoAction", 14: "DefineSound",
  20: "DefineBitsLossless", 21: "DefineBitsJPEG2", 35: "DefineBitsJPEG3", 36: "DefineBitsLossless2",
  39: "DefineSprite", 41: "ProductInfo", 43: "FrameLabel", 56: "ExportAssets", 59: "DoInitAction",
  64: "EnableDebugger2", 65: "ScriptLimits", 69: "FileAttributes", 71: "ImportAssets2",
  76: "SymbolClass", 77: "Metadata", 82: "DoABC", 87: "DefineBinaryData", 90: "DefineBitsJPEG4"
};

const renderMovie = (parsed: SwfParseResult): string => {
  const movie = parsed.movie;
  if (!movie) return "";
  // RECT coordinates are twips (1/20 pixel); FrameRate is 8.8 fixed-point.
  return renderDefinitionRow("Stage size", `${(movie.xMax - movie.xMin) / 20} × ` +
    `${(movie.yMax - movie.yMin) / 20} pixels`) +
    renderDefinitionRow("Frame rate", `${movie.frameRate / 256} fps`) +
    renderDefinitionRow("Declared frames", String(movie.frameCount));
};

const renderAttributes = (flags: number | undefined): string => {
  if (flags == null) return "";
  return renderDefinitionRow("FileAttributes", hex(flags, 8)) +
    renderDefinitionRow("ActionScript flag", flags & 8 ? "ActionScript 3" : "ActionScript 1/2") +
    renderDefinitionRow("Local-file access preference", flags & 1 ? "Network access" : "Local file access",
      "Declared UseNetwork preference, not evidence of network or file activity.");
};

const renderTagSummary = (parsed: SwfParseResult): string => {
  if (!parsed.tags?.length) return "";
  return `<div class="tableWrap"><table class="table"><caption>Top-level SWF tags</caption>` +
    `<thead><tr><th class="peNumeric">Code</th><th>Tag</th><th class="peNumeric">Count</th>` +
    `<th class="peNumeric">Body bytes</th></tr></thead><tbody>` +
    parsed.tags.map(tag => `<tr><td class="mono peNumeric">${tag.code}</td>` +
      `<td>${TAG_NAMES[tag.code] ?? "Unknown tag"}</td><td class="peNumeric">${tag.count}</td>` +
      `<td class="peNumeric">${humanSize(tag.bodyBytes)}</td></tr>`).join("") +
    `</tbody></table></div>`;
};

export const renderSwf = (parsed: SwfParseResult, start = 0, end?: number): string => {
  return `<section data-swf-panel data-swf-start="${start}"` +
    (end == null ? "" : ` data-swf-end="${end}"`) + `><h3>Flash SWF</h3><dl>` +
    renderDefinitionRow("Signature", parsed.signature) +
    renderDefinitionRow("SWF version", String(parsed.version)) +
    renderDefinitionRow("Compression", { FWS: "None", CWS: "zlib", ZWS: "LZMA" }[parsed.signature]) +
    renderDefinitionRow("Declared uncompressed size", humanSize(parsed.fileLength)) +
    renderMovie(parsed) + renderAttributes(parsed.fileAttributes) + `</dl>` +
    (parsed.signature !== "FWS" && parsed.tags == null && !parsed.issues.length
      ? `<p class="smallNote" data-swf-body-status>Compressed SWF header inspected. ` +
        `Automatic background analysis of the tag chain and compressed stream is running.</p>` : "") +
    `<p class="smallNote">Tag inspection covers the outer structure. Nested tag bodies and ` +
    `ActionScript bytecode are not validated or executed.</p>` +
    (parsed.issues.length ? `<ul class="issueList">` +
      parsed.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("") + `</ul>` : "") +
    renderTagSummary(parsed) + `</section>`;
};
