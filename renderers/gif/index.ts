// @ts-nocheck
"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";

function renderLoopInfo(loopCount) {
  if (loopCount == null) return "Not specified (plays once by default)";
  if (loopCount === 0) return "0 (loop forever)";
  return `${loopCount} time${loopCount === 1 ? "" : "s"}`;
}

function renderPixelAspect(ratio) {
  if (ratio == null) return "Not specified";
  const rounded = Math.round(ratio * 100) / 100;
  return `${rounded}:1 (encoded as ${(ratio * 64 - 15).toFixed(0)})`;
}

function renderWarnings(warnings) {
  if (!warnings || warnings.length === 0) return "";
  const items = warnings
    .map(warning => `<li>${escapeHtml(warning)}</li>`)
    .join("");
  return `<div class="warnBox"><div class="warnTitle">Warnings</div><ul>${items}</ul></div>`;
}

function renderComments(comments) {
  if (!comments || comments.length === 0) return "";
  const items = comments
    .map((comment, index) => {
      const label = comments.length === 1 ? "Comment" : `Comment #${index + 1}`;
      const suffix = comment.truncated ? " (truncated preview)" : "";
      return `<li><strong>${escapeHtml(label)}:</strong> ${escapeHtml(
        (comment.text || "") + suffix
      )}</li>`;
    })
    .join("");
  return `<div><h4>Comments</h4><ul>${items}</ul></div>`;
}

function renderApplicationExtensions(apps) {
  if (!apps || apps.length === 0) return "";
  const rows = apps
    .map(app => {
      const loopText =
        app.loopCount == null
          ? "-"
          : app.loopCount === 0
            ? "Loop forever"
            : `${app.loopCount} loop${app.loopCount === 1 ? "" : "s"}`;
      const sizeText = `${app.dataSize} bytes`;
      const truncated = app.truncated ? " (truncated)" : "";
      const auth = app.authCode ? ` (${escapeHtml(app.authCode)})` : "";
      return `<tr><td>${escapeHtml(app.identifier || "")}${auth}</td>` +
        `<td>${escapeHtml(loopText)}</td>` +
        `<td>${escapeHtml(sizeText + truncated)}</td></tr>`;
    })
    .join("");
  return (
    "<h4>Application extensions</h4>" +
    '<table class="byteView"><thead><tr>' +
    "<th>Identifier</th><th>Loops</th><th>Data size</th>" +
    "</tr></thead><tbody>" +
    rows +
    "</tbody></table>"
  );
}

function renderFrames(frames) {
  if (!frames || frames.length === 0) return "";
  const header =
    "<h4>Frames</h4>" +
    '<table class="byteView"><thead><tr>' +
    "<th>#</th><th>Position</th><th>Size</th><th>Interlaced</th>" +
    "<th>Delay (ms)</th><th>Disposal</th><th>Transparency</th>" +
    "<th>Color table</th><th>LZW min code</th><th>Data bytes</th>" +
    "</tr></thead><tbody>";
  const rows = frames
    .map((frame, index) => {
      const delay = frame?.gce?.delayMs ?? 0;
      const disposal = frame?.gce?.disposalMethod || "Not provided";
      const transparency =
        frame?.gce?.transparentColorIndex != null
          ? `Index ${frame.gce.transparentColorIndex}`
          : "None";
      const colorTable = frame.hasLocalColorTable
        ? `${frame.localColorCount} (local${frame.localColorTableSorted ? ", sorted" : ""})`
        : "Global";
      const data = `${frame.dataSize} bytes${frame.dataTruncated ? " (truncated)" : ""}`;
      return "<tr>" +
        `<td>${index}</td>` +
        `<td>${frame.left},${frame.top}</td>` +
        `<td>${frame.width}×${frame.height}</td>` +
        `<td>${frame.interlaced ? "Yes" : "No"}</td>` +
        `<td>${delay}</td>` +
        `<td title="${escapeHtml(disposal)}">${escapeHtml(disposal)}</td>` +
        `<td>${escapeHtml(transparency)}</td>` +
        `<td>${escapeHtml(colorTable)}</td>` +
        `<td>${frame.lzwMinCodeSize}</td>` +
        `<td title="${toHex32(frame.dataSize)}">${escapeHtml(data)}</td>` +
        "</tr>";
    })
    .join("");
  return header + rows + "</tbody></table>";
}

export function renderGif(gif) {
  if (!gif) return "";
  const {
    size,
    version,
    width,
    height,
    hasGlobalColorTable,
    globalColorCount,
    globalColorTableSorted,
    colorResolutionBits,
    backgroundColorIndex,
    pixelAspectRatio,
    frameCount,
    frames,
    loopCount,
    comments,
    applicationExtensions,
    plainTextCount,
    hasTrailer,
    overlayBytes,
    warnings
  } = gif;

  const out = [];
  out.push("<h3>GIF structure</h3>");
  out.push("<dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(size))));
  out.push(renderDefinitionRow("Version", escapeHtml(version)));
  out.push(renderDefinitionRow("Dimensions", `${width} × ${height} px`));
  out.push(renderDefinitionRow("Frames", String(frameCount)));
  out.push(
    renderDefinitionRow(
      "Animation loops",
      escapeHtml(renderLoopInfo(loopCount)),
      "Loop count comes from the NETSCAPE application extension. 0 means infinite."
    )
  );
  out.push(
    renderDefinitionRow(
      "Pixel aspect ratio",
      escapeHtml(renderPixelAspect(pixelAspectRatio)),
      "GIF encodes an optional pixel aspect hint; most viewers ignore it."
    )
  );
  out.push(
    renderDefinitionRow(
      "Global color table",
      hasGlobalColorTable
        ? `${globalColorCount} colors${globalColorTableSorted ? " (sorted)" : ""}`
        : "Not present"
    )
  );
  out.push(
    renderDefinitionRow(
      "Color resolution",
      `${colorResolutionBits} bits per channel`,
      "Number of bits of color resolution declared in the logical screen descriptor."
    )
  );
  out.push(
    renderDefinitionRow(
      "Background color index",
      hasGlobalColorTable ? `${backgroundColorIndex}` : "Not defined",
      "Index into the global color table used when no frame pixels cover the canvas."
    )
  );
  out.push(
    renderDefinitionRow(
      "Plain text extensions",
      plainTextCount > 0 ? `${plainTextCount} found` : "None detected"
    )
  );
  out.push(
    renderDefinitionRow(
      "Trailer",
      hasTrailer ? "Present" : "Missing",
      "GIF files should end with 0x3B (trailer)."
    )
  );
  if (overlayBytes > 0) {
    out.push(
      renderDefinitionRow(
        "Trailing data",
        `${overlayBytes} bytes after trailer`,
        "Extra bytes after the GIF trailer may indicate an embedded payload."
      )
    );
  }
  out.push("</dl>");

  out.push(renderWarnings(warnings));
  out.push(renderComments(comments));
  out.push(renderApplicationExtensions(applicationExtensions));
  out.push(renderFrames(frames));

  return out.join("");
}
