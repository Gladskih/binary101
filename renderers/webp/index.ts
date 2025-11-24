// @ts-nocheck
"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";

function renderIssues(issues) {
  if (!issues || issues.length === 0) return "";
  const items = issues
    .map(issue => `<li>${escapeHtml(issue)}</li>`)
    .join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
}

function describeFormat(code) {
  if (code === "VP8") return "Lossy bitstream (VP8)";
  if (code === "VP8L") return "Lossless bitstream (VP8L)";
  if (code === "VP8X") return "Extended file (VP8X canvas)";
  return "Unknown WebP variant";
}

function describeDimensions(dimensions) {
  if (!dimensions) return "Unknown";
  const { width, height, source } = dimensions;
  const suffix = source ? ` (${escapeHtml(source)})` : "";
  if (!width || !height) return `Unknown${suffix}`;
  return `${width} x ${height} px${suffix}`;
}

function describeAnimation(webp) {
  if (!webp.hasAnimation) return "No animation markers";
  const frames =
    webp.frameCount > 0 ? `${webp.frameCount} frame(s)` : "Unknown frame count";
  const loop =
    webp.animationInfo && webp.animationInfo.loopCount != null
      ? `, loop count ${webp.animationInfo.loopCount}`
      : "";
  return `Yes (${frames}${loop})`;
}

function describeBackgroundColor(webp) {
  if (
    !webp.animationInfo ||
    webp.animationInfo.backgroundColor == null
  ) {
    return "Not set";
  }
  return toHex32(webp.animationInfo.backgroundColor, 8);
}

function renderChunks(chunks) {
  if (!chunks || chunks.length === 0) return "";
  const header =
    "<h4>Chunks</h4>" +
    "<p>Each WebP file is a RIFF container made of four-character chunks. " +
    "Offsets are measured from the start of the file. Sizes are reported " +
    "without the padding byte used for even alignment.</p>";
  const rows = chunks
    .map((chunk, index) => {
      const type = escapeHtml(chunk.type || "");
      const offset = chunk.offset != null ? chunk.offset : 0;
      const size = chunk.size != null ? chunk.size : 0;
      const padded = chunk.paddedSize != null ? chunk.paddedSize : size;
      const truncated = chunk.truncated ? " class=\"dim\"" : "";
      return (
        `<tr${truncated}>` +
        `<td>${index}</td>` +
        `<td>${type}</td>` +
        `<td title="${toHex32(offset, 8)}">${offset}</td>` +
        `<td title="${toHex32(size, 8)}">${size} B</td>` +
        `<td title="${toHex32(padded, 8)}">${padded} B</td>` +
        "</tr>"
      );
    })
    .join("");
  return (
    header +
    '<table class="byteView"><thead><tr>' +
    "<th>#</th><th>Type</th><th>Offset</th><th>Size</th><th>Padded</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
}

export function renderWebp(webp) {
  if (!webp) return "";
  const { chunkStats, issues } = webp;
  const out = [];
  out.push("<h3>WebP structure</h3>");
  out.push("<dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(webp.size))));
  out.push(renderDefinitionRow("Format", escapeHtml(describeFormat(webp.format))));
  out.push(
    renderDefinitionRow(
      "Dimensions",
      escapeHtml(describeDimensions(webp.dimensions)),
      "Derived from the VP8/VP8L bitstream or the VP8X canvas header."
    )
  );
  out.push(
    renderDefinitionRow(
      "Alpha",
      webp.hasAlpha
        ? "Alpha present (ALPH chunk or VP8X flag)"
        : "No alpha markers"
    )
  );
  out.push(
    renderDefinitionRow(
      "Animation",
      escapeHtml(describeAnimation(webp)),
      "Reported from VP8X flags, ANIM header, and ANMF frame chunks."
    )
  );
  out.push(
    renderDefinitionRow(
      "Animation background",
      escapeHtml(describeBackgroundColor(webp)),
      "ANIM chunk defines background color and loop count for animated images."
    )
  );
  out.push(
    renderDefinitionRow(
      "ICC profile",
      webp.hasIccProfile ? "Embedded ICCP chunk" : "Not present"
    )
  );
  out.push(
    renderDefinitionRow("EXIF metadata", webp.hasExif ? "Present" : "Not present")
  );
  out.push(
    renderDefinitionRow("XMP metadata", webp.hasXmp ? "Present" : "Not present")
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
  out.push(renderChunks(webp.chunks));
  return out.join("");
}
