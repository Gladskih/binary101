"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";
import { renderChunkTable } from "../riff/chunk-table.js";
import type { AviParseResult, AviStream, AviVideoFormat } from "../../analyzers/avi/types.js";
import type { WaveFormatInfo } from "../../analyzers/riff/wave-format.js";

const renderIssues = (issues: string[] | null | undefined): string => {
  if (!issues || issues.length === 0) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
};

const describeStreamRate = (stream: AviStream): string => {
  const header = stream.header;
  if (!header) return "Unknown";
  if (header.scale && header.rate) {
    const value = header.rate / header.scale;
    return `${Math.round(value * 1000) / 1000} /s`;
  }
  return "Unknown";
};

const describeStreamFormat = (stream: AviStream): string => {
  if (stream.header?.type === "vids") {
    const fmt =
      stream.format && "width" in stream.format
        ? (stream.format as AviVideoFormat)
        : null;
    if (!fmt) return "Video stream";
    const parts = [];
    if (fmt.width && fmt.height) parts.push(`${fmt.width}x${fmt.height}`);
    if (fmt.bitCount != null) parts.push(`${fmt.bitCount}-bit`);
    if (fmt.compression) parts.push(fmt.compression);
    return parts.length ? parts.join(", ") : "Video stream";
  }
  if (stream.header?.type === "auds") {
    const fmt =
      stream.format && "audioFormat" in stream.format
        ? (stream.format as WaveFormatInfo)
        : null;
    if (!fmt) return "Audio stream";
    const parts = [];
    if (fmt.formatName) parts.push(fmt.formatName);
    if (fmt.channels) parts.push(`${fmt.channels}ch`);
    if (fmt.sampleRate) parts.push(`${fmt.sampleRate}Hz`);
    if (fmt.bitsPerSample) parts.push(`${fmt.bitsPerSample}-bit`);
    return parts.length ? parts.join(", ") : "Audio stream";
  }
  return stream.header?.type || "Stream";
};

const renderStreamIssues = (stream: AviStream): string => {
  if (!stream.issues.length) return "";
  const items = stream.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<ul class="issueList">${items}</ul>`;
};

const renderStreams = (streams: AviStream[]): string => {
  if (!streams || streams.length === 0) return "";
  const rows = streams
    .map(stream => {
      return (
        "<tr>" +
        `<td>${stream.index}</td>` +
        `<td>${escapeHtml(stream.header?.type || "Unknown")}</td>` +
        `<td>${escapeHtml(stream.header?.handler || "")}</td>` +
        `<td>${escapeHtml(describeStreamRate(stream))}</td>` +
        `<td>${escapeHtml(describeStreamFormat(stream))}</td>` +
        `<td>${escapeHtml(stream.name || "")}${renderStreamIssues(stream)}</td>` +
        "</tr>"
      );
    })
    .join("");
  return (
    "<h4>Streams</h4>" +
    '<table class="byteView"><thead><tr>' +
    "<th>#</th><th>Type</th><th>Handler</th><th>Rate</th><th>Format</th><th>Notes</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
};

const renderInfoTags = (avi: AviParseResult): string => {
  if (!avi.infoTags || avi.infoTags.length === 0) return "";
  const rows = avi.infoTags
    .map(tag => {
      const dim = tag.truncated ? ' class="dim"' : "";
      return `<tr${dim}><td>${escapeHtml(tag.id)}</td><td>${escapeHtml(tag.value)}</td></tr>`;
    })
    .join("");
  return (
    "<h4>INFO metadata</h4>" +
    '<table class="byteView"><thead><tr><th>Tag</th><th>Value</th></tr></thead>' +
    `<tbody>${rows}</tbody></table>`
  );
};

export const renderAvi = (avi: AviParseResult | null | unknown): string => {
  const data = avi as AviParseResult | null;
  if (!data) return "";
  const out: string[] = [];
  out.push("<h3>AVI container</h3>");
  out.push("<dl>");
  out.push(
    renderDefinitionRow(
      "File size",
      escapeHtml(formatHumanSize(data.riff.fileSize))
    )
  );
  out.push(
    renderDefinitionRow(
      "Frame size",
      data.mainHeader?.width && data.mainHeader.height
        ? `${data.mainHeader.width} x ${data.mainHeader.height}`
        : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Frame rate",
      data.mainHeader?.frameRate ? `${data.mainHeader.frameRate} fps` : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Duration",
      data.mainHeader?.durationSeconds != null
        ? `${data.mainHeader.durationSeconds} s`
        : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Streams",
      data.mainHeader?.streams != null
        ? `${data.mainHeader.streams} declared (${data.streams.length} parsed)`
        : String(data.streams.length)
    )
  );
  out.push(
    renderDefinitionRow(
      "Chunks parsed",
      String(data.riff.stats.chunkCount),
      "RIFF chunk count across the file."
    )
  );
  out.push(
    renderDefinitionRow(
      "Unparsed tail",
      data.riff.stats.overlayBytes ? `${data.riff.stats.overlayBytes} B` : "None"
    )
  );
  out.push("</dl>");
  out.push(renderIssues(data.issues));
  out.push(renderStreams(data.streams));
  out.push(renderInfoTags(data));
  out.push(renderChunkTable(data.riff.chunks));
  return out.join("");
};
