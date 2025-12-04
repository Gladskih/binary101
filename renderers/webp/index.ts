"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import { renderChunkTable } from "../riff/chunk-table.js";
import type { WebpParseResult } from "../../analyzers/webp/types.js";

function renderIssues(issues: string[] | null | undefined): string {
  if (!issues || issues.length === 0) return "";
  const items = issues
    .map(issue => `<li>${escapeHtml(issue)}</li>`)
    .join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
}

function describeFormat(code: string | null): string {
  if (code === "VP8") return "Lossy bitstream (VP8)";
  if (code === "VP8L") return "Lossless bitstream (VP8L)";
  if (code === "VP8X") return "Extended file (VP8X canvas)";
  return "Unknown WebP variant";
}

function describeDimensions(
  dimensions: WebpParseResult["dimensions"] | undefined
): string {
  if (!dimensions) return "Unknown";
  const { width, height, source } = dimensions;
  const suffix = source ? ` (${escapeHtml(source)})` : "";
  if (!width || !height) return `Unknown${suffix}`;
  return `${width} x ${height} px${suffix}`;
}

function describeAnimation(webp: WebpParseResult): string {
  if (!webp.hasAnimation) return "No animation markers";
  const frames =
    webp.frameCount > 0 ? `${webp.frameCount} frame(s)` : "Unknown frame count";
  const loop =
    webp.animationInfo && webp.animationInfo.loopCount != null
      ? `, loop count ${webp.animationInfo.loopCount}`
      : "";
  return `Yes (${frames}${loop})`;
}

function describeBackgroundColor(webp: WebpParseResult): string {
  if (!webp.animationInfo || webp.animationInfo.backgroundColor == null) {
    return "Not set";
  }
  return toHex32(webp.animationInfo.backgroundColor, 8);
}

export function renderWebp(webp: WebpParseResult | null | unknown): string {
  const data = webp as WebpParseResult | null;
  if (!data) return "";
  const { chunkStats, issues } = data;
  const out = [];
  out.push("<h3>WebP structure</h3>");
  out.push("<dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(data.size))));
  out.push(renderDefinitionRow("Format", escapeHtml(describeFormat(data.format))));
  out.push(
    renderDefinitionRow(
      "Dimensions",
      escapeHtml(describeDimensions(data.dimensions)),
      "Derived from the VP8/VP8L bitstream or the VP8X canvas header."
    )
  );
  out.push(
    renderDefinitionRow(
      "Alpha",
      data.hasAlpha
        ? "Alpha present (ALPH chunk or VP8X flag)"
        : "No alpha markers"
    )
  );
  out.push(
    renderDefinitionRow(
      "Animation",
      escapeHtml(describeAnimation(data)),
      "Reported from VP8X flags, ANIM header, and ANMF frame chunks."
    )
  );
  out.push(
    renderDefinitionRow(
      "Animation background",
      escapeHtml(describeBackgroundColor(data)),
      "ANIM chunk defines background color and loop count for animated images."
    )
  );
  out.push(
    renderDefinitionRow(
      "ICC profile",
      data.hasIccProfile ? "Embedded ICCP chunk" : "Not present"
    )
  );
  out.push(
    renderDefinitionRow("EXIF metadata", data.hasExif ? "Present" : "Not present")
  );
  out.push(
    renderDefinitionRow("XMP metadata", data.hasXmp ? "Present" : "Not present")
  );
  if (chunkStats) {
    out.push(
      renderDefinitionRow(
        "Chunks parsed",
        chunkStats.chunkCount != null ? String(chunkStats.chunkCount) : "Unknown"
      )
    );
    out.push(
      renderDefinitionRow(
        "Unparsed tail",
        chunkStats.overlayBytes ? `${chunkStats.overlayBytes} B` : "None"
      )
    );
  }
  out.push("</dl>");
  out.push(renderIssues(issues));
  out.push(renderChunkTable(data.chunks));
  return out.join("");
}
