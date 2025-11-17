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

function formatBoolean(value) {
  return value ? "Yes" : "No";
}

function renderWarnings(issues) {
  if (!issues || issues.length === 0) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
}

function renderSummary(mp3) {
  const { summary, audioDataBytes } = mp3;
  if (!summary) return "";
  const rows = [];
  rows.push(renderDefinitionRow("MPEG version", escapeHtml(summary.mpegVersion || "Unknown")));
  rows.push(renderDefinitionRow("Layer", escapeHtml(summary.layer || "Unknown")));
  rows.push(renderDefinitionRow("Channel mode", escapeHtml(summary.channelMode || "Unknown")));
  rows.push(
    renderDefinitionRow(
      "Sample rate",
      summary.sampleRateHz ? `${summary.sampleRateHz} Hz` : "Unknown"
    )
  );
  rows.push(
    renderDefinitionRow(
      "Average bitrate",
      summary.bitrateKbps ? `${summary.bitrateKbps} kbps` : "Unknown"
    )
  );
  rows.push(
    renderDefinitionRow("Duration", formatDuration(summary.durationSeconds))
  );
  rows.push(
    renderDefinitionRow(
      "Audio payload offset",
      summary.audioDataOffset != null ? `${summary.audioDataOffset} B` : "Unknown"
    )
  );
  rows.push(
    renderDefinitionRow(
      "Estimated audio bytes",
      audioDataBytes ? formatHumanSize(audioDataBytes) : "Unknown"
    )
  );
  rows.push(renderDefinitionRow("VBR", formatBoolean(summary.isVbr)));
  rows.push(renderDefinitionRow("ID3v2 tag", formatBoolean(summary.hasId3v2)));
  rows.push(renderDefinitionRow("ID3v1 tag", formatBoolean(summary.hasId3v1)));
  rows.push(renderDefinitionRow("APE tag", formatBoolean(summary.hasApeTag)));
  rows.push(renderDefinitionRow("Lyrics3 tag", formatBoolean(summary.hasLyrics3)));
  return "<h4>Summary</h4><dl>" + rows.join("") + "</dl>";
}

function renderMpeg(mpeg) {
  if (!mpeg || !mpeg.firstFrame) return "";
  const f = mpeg.firstFrame;
  const rows = [];
  rows.push(renderDefinitionRow("Frame offset", `${f.offset} B`));
  rows.push(
    renderDefinitionRow(
      "Frame length",
      f.frameLengthBytes ? `${f.frameLengthBytes} B` : "Unknown"
    )
  );
  rows.push(renderDefinitionRow("Samples per frame", f.samplesPerFrame || "Unknown"));
  rows.push(renderDefinitionRow("CRC present", formatBoolean(f.hasCrc)));
  rows.push(renderDefinitionRow("Padding", formatBoolean(f.padding)));
  rows.push(renderDefinitionRow("Private bit", formatBoolean(f.privateBit)));
  rows.push(renderDefinitionRow("Copyright", formatBoolean(f.copyright)));
  rows.push(renderDefinitionRow("Original", formatBoolean(f.original)));
  if (f.modeExtension) {
    rows.push(renderDefinitionRow("Mode extension", escapeHtml(f.modeExtension)));
  }
  if (f.emphasis && f.emphasis !== "None") {
    rows.push(renderDefinitionRow("Emphasis", escapeHtml(f.emphasis)));
  }
  if (mpeg.secondFrameValidated === false) {
    rows.push(renderDefinitionRow("Second frame", "Validation failed"));
  } else if (mpeg.secondFrameValidated === true) {
    rows.push(renderDefinitionRow("Second frame", "Validated"));
  }
  if (mpeg.nonAudioBytes != null) {
    rows.push(renderDefinitionRow("Non-audio bytes", formatHumanSize(mpeg.nonAudioBytes)));
  }
  return "<h4>MPEG audio stream</h4><dl>" + rows.join("") + "</dl>";
}

function renderVbr(vbr) {
  if (!vbr) return "";
  const rows = [];
  rows.push(renderDefinitionRow("Header", escapeHtml(vbr.type)));
  if (vbr.frames != null) rows.push(renderDefinitionRow("Total frames", String(vbr.frames)));
  if (vbr.bytes != null) rows.push(renderDefinitionRow("Total bytes", String(vbr.bytes)));
  if (vbr.quality != null) rows.push(renderDefinitionRow("Quality", String(vbr.quality)));
  if (vbr.lameEncoder) rows.push(renderDefinitionRow("Encoder", escapeHtml(vbr.lameEncoder)));
  return "<h4>VBR info</h4><dl>" + rows.join("") + "</dl>";
}

function renderId3v2Frames(frames) {
  if (!frames || frames.length === 0) return "<p>No frames parsed.</p>";
  const rows = frames
    .map(frame => {
      const id = escapeHtml(frame.id || "?");
      const size = frame.size != null ? `${frame.size} B` : "";
      const detail = frame.detail || {};
      if (detail.type === "text") {
        const parts = [];
        if (detail.description) parts.push(`<strong>${escapeHtml(detail.description)}:</strong>`);
        parts.push(escapeHtml(detail.value || "(empty)"));
        return `<tr><td>${id}</td><td>${parts.join(" ")}</td><td>${size}</td></tr>`;
      }
      if (detail.type === "url") {
        const desc = detail.description
          ? `${escapeHtml(detail.description)} → `
          : "";
        const url = escapeHtml(detail.url || "");
        return `<tr><td>${id}</td><td>${desc}${url}</td><td>${size}</td></tr>`;
      }
      if (detail.type === "apic") {
        const desc = detail.description
          ? ` (${escapeHtml(detail.description)})`
          : "";
        const info = `${escapeHtml(detail.pictureType)}${desc}, ${detail.imageSize} bytes, ${
          escapeHtml(detail.mimeType)
        }`;
        return `<tr><td>${id}</td><td>${info}</td><td>${size}</td></tr>`;
      }
      const preview = escapeHtml(detail.preview || "(binary)");
      return `<tr><td>${id}</td><td>${preview}</td><td>${size}</td></tr>`;
    })
    .join("");
  const tableHead =
    '<table class="byteView"><thead><tr><th>Frame</th><th>Value</th>' +
    '<th>Size</th></tr></thead><tbody>';
  return tableHead + rows + "</tbody></table>";
}

function renderId3v2(id3) {
  if (!id3) return "";
  const details = [];
  const version = `${id3.versionMajor}.${id3.versionRevision}`;
  details.push(renderDefinitionRow("Version", escapeHtml(version)));
  details.push(renderDefinitionRow("Extended header", formatBoolean(id3.flags.extendedHeader)));
  details.push(renderDefinitionRow("Footer present", formatBoolean(id3.hasFooter)));
  details.push(
    renderDefinitionRow(
      "Unsynchronisation",
      formatBoolean(id3.flags.unsynchronisation)
    )
  );
  if (id3.extendedHeaderSize) {
    details.push(renderDefinitionRow("Extended header size", `${id3.extendedHeaderSize} B`));
  }
  details.push(renderDefinitionRow("Declared tag size", `${id3.size} B`));
  const framesTable = renderId3v2Frames(id3.frames);
  return "<h4>ID3v2 metadata</h4><dl>" + details.join("") + "</dl>" + framesTable;
}

function renderId3v1(id3v1) {
  if (!id3v1) return "";
  const rows = [];
  rows.push(renderDefinitionRow("Title", escapeHtml(id3v1.title || "(empty)")));
  rows.push(renderDefinitionRow("Artist", escapeHtml(id3v1.artist || "(empty)")));
  rows.push(renderDefinitionRow("Album", escapeHtml(id3v1.album || "(empty)")));
  rows.push(renderDefinitionRow("Year", escapeHtml(id3v1.year || "(empty)")));
  rows.push(renderDefinitionRow("Comment", escapeHtml(id3v1.comment || "(empty)")));
  if (id3v1.trackNumber != null) {
    rows.push(renderDefinitionRow("Track", String(id3v1.trackNumber)));
  }
  const genreText = id3v1.genreName || `(code ${id3v1.genreCode})`;
  rows.push(renderDefinitionRow("Genre", escapeHtml(genreText)));
  return "<h4>ID3v1 tag</h4><dl>" + rows.join("") + "</dl>";
}

function renderApe(ape) {
  if (!ape) return "";
  const rows = [];
  rows.push(renderDefinitionRow("Version", `0x${ape.version.toString(16)}`));
  rows.push(renderDefinitionRow("Size", `${ape.size || "Unknown"} B`));
  rows.push(
    renderDefinitionRow(
      "Items",
      ape.itemCount != null ? String(ape.itemCount) : "Unknown"
    )
  );
  rows.push(renderDefinitionRow("Offset", `${ape.offset} B`));
  return "<h4>APE tag</h4><dl>" + rows.join("") + "</dl>";
}

function renderLyrics(lyrics) {
  if (!lyrics) return "";
  const rows = [];
  rows.push(renderDefinitionRow("Version", escapeHtml(lyrics.version)));
  if (lyrics.sizeEstimate != null) {
    rows.push(renderDefinitionRow("Size", `${lyrics.sizeEstimate} B`));
  }
  if (lyrics.offset != null) rows.push(renderDefinitionRow("Offset", `${lyrics.offset} B`));
  return "<h4>Lyrics3</h4><dl>" + rows.join("") + "</dl>";
}

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
