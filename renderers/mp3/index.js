"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";

function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "Unknown";
  const rounded = Math.round(seconds);
  const minutes = Math.floor(rounded / 60);
  const secs = rounded % 60;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  if (hours > 0) {
    return `${hours}:${mins.toString().padStart(2, "0")}:${secs
      .toString()
      .padStart(2, "0")}`;
  }
  return `${minutes}:${secs.toString().padStart(2, "0")}`;
}

function renderIssues(issues) {
  if (!issues || issues.length === 0) return "";
  const items = issues
    .map(issue => `<li>${escapeHtml(issue)}</li>`)
    .join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
}

function renderId3v2(id3) {
  if (!id3) return "";
  const rows = id3.frames
    .map(frame => {
      const id = escapeHtml(frame.id || "?");
      const size = frame.size != null ? `${frame.size} B` : "";
      const value = escapeHtml(frame.value || "(empty)");
      return `<tr><td>${id}</td><td>${value}</td><td>${size}</td></tr>`;
    })
    .join("");
  const version = `${id3.versionMajor}.${id3.versionRevision}`;
  return (
    "<h4>ID3v2 metadata</h4>" +
    `<p>Version ${escapeHtml(version)}${id3.flags.footerPresent ?
      ", footer present" : ""}. Parsed up to ${id3.frames.length} frames.</p>` +
    '<table class="byteView"><thead><tr>' +
    "<th>Frame</th><th>Value</th><th>Size</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
}

function renderId3v1(id3v1) {
  if (!id3v1) return "";
  return (
    "<h4>ID3v1 tag</h4>" +
    "<dl>" +
    renderDefinitionRow("Title", escapeHtml(id3v1.title || "(empty)")) +
    renderDefinitionRow("Artist", escapeHtml(id3v1.artist || "(empty)")) +
    renderDefinitionRow("Album", escapeHtml(id3v1.album || "(empty)")) +
    renderDefinitionRow("Year", escapeHtml(id3v1.year || "(empty)")) +
    renderDefinitionRow("Comment", escapeHtml(id3v1.comment || "(empty)")) +
    renderDefinitionRow("Genre code", String(id3v1.genreCode)) +
    "</dl>"
  );
}

function renderVbr(vbr) {
  if (!vbr) return "";
  const rows = [];
  rows.push(renderDefinitionRow("Header", escapeHtml(vbr.tag)));
  if (vbr.frames != null) rows.push(renderDefinitionRow("Frames", String(vbr.frames)));
  if (vbr.bytes != null) rows.push(renderDefinitionRow("Bytes", String(vbr.bytes)));
  if (vbr.quality != null) rows.push(renderDefinitionRow("Quality", String(vbr.quality)));
  if (vbr.lameEncoder) {
    rows.push(renderDefinitionRow("Encoder", escapeHtml(vbr.lameEncoder)));
  }
  return "<h4>VBR header</h4><dl>" + rows.join("") + "</dl>";
}

function renderFrame(frame) {
  if (!frame) return "";
  const rows = [];
  rows.push(renderDefinitionRow("Version", escapeHtml(frame.versionLabel)));
  rows.push(renderDefinitionRow("Layer", escapeHtml(frame.layerLabel)));
  rows.push(
    renderDefinitionRow(
      "Bitrate",
      frame.bitrateKbps ? `${frame.bitrateKbps} kbps` : "Unknown"
    )
  );
  rows.push(
    renderDefinitionRow(
      "Sample rate",
      frame.sampleRate ? `${frame.sampleRate} Hz` : "Unknown"
    )
  );
  rows.push(renderDefinitionRow("Channels", escapeHtml(frame.channelMode)));
  rows.push(renderDefinitionRow("Padding", frame.padding ? "Yes" : "No"));
  rows.push(renderDefinitionRow("First frame offset", `${frame.offset} B`));
  return "<h4>Audio stream</h4><dl>" + rows.join("") + "</dl>";
}

export function renderMp3(mp3) {
  if (!mp3) return "";
  const { size, firstFrame, durationSeconds, audioBytes, vbr, id3v2, id3v1, issues } = mp3;
  const out = [];
  out.push("<h3>MPEG audio (MP3)</h3>");
  out.push("<dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(size))));
  out.push(
    renderDefinitionRow(
      "Audio data",
      audioBytes ? `${formatHumanSize(audioBytes)}` : "Unknown",
      "Approximate audio payload after skipping metadata tags."
    )
  );
  out.push(
    renderDefinitionRow("Estimated duration", formatDuration(durationSeconds))
  );
  out.push("</dl>");
  out.push(renderFrame(firstFrame));
  out.push(renderVbr(vbr));
  out.push(renderId3v2(id3v2));
  out.push(renderId3v1(id3v1));
  out.push(renderIssues(issues));
  return out.join("");
}
