"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import type { Mp4ParseResult, Mp4Track } from "../../analyzers/mp4/types.js";

const renderIssues = (issues: string[] | null | undefined): string => {
  if (!issues || issues.length === 0) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
};

const formatDuration = (seconds: number | null | undefined): string => {
  if (seconds == null || Number.isNaN(seconds)) return "Unknown";
  if (seconds < 0.001) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 10) return `${Math.round(seconds * 1000) / 1000} s`;
  if (seconds < 600) return `${Math.round(seconds * 10) / 10} s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = Math.round(seconds - minutes * 60);
  return `${minutes} min ${remaining} s`;
};

const describeTrackCodec = (track: Mp4Track): string => {
  const codec = track.codec;
  if (!codec) return "Unknown";
  const parts: string[] = [];
  if (codec.codecString) parts.push(codec.codecString);
  if (codec.description && codec.description !== codec.codecString) parts.push(codec.description);
  if (!parts.length && codec.format) parts.push(codec.format);
  if (codec.profile) parts.push(codec.profile);
  if (codec.level) parts.push(codec.level);
  return parts.length ? parts.join(", ") : "Unknown";
};

const describeTrackDetails = (track: Mp4Track): string => {
  if (track.kind === "video") {
    const parts: string[] = [];
    if (track.width && track.height) parts.push(`${track.width} x ${track.height}`);
    if (track.codec?.pixelAspectRatio) parts.push(`PAR ${track.codec.pixelAspectRatio}`);
    if (track.sampleCount != null) parts.push(`${track.sampleCount} samples`);
    if (track.keyframeCount != null) parts.push(`${track.keyframeCount} keyframes`);
    return parts.length ? parts.join(", ") : "No video details";
  }
  if (track.kind === "audio") {
    const parts: string[] = [];
    if (track.codec?.sampleRate) parts.push(`${Math.round(track.codec.sampleRate)} Hz`);
    if (track.codec?.channels) parts.push(`${track.codec.channels} ch`);
    if (track.codec?.bitDepth) parts.push(`${track.codec.bitDepth}-bit`);
    if (track.sampleCount != null) parts.push(`${track.sampleCount} samples`);
    return parts.length ? parts.join(", ") : "No audio details";
  }
  return "No details";
};

const renderTrackWarnings = (track: Mp4Track, index: number): string => {
  if (!track.warnings || track.warnings.length === 0) return "";
  const items = track.warnings.map(w => `<li>${escapeHtml(w)}</li>`).join("");
  return `<div class="dim">Track ${index + 1} warnings:<ul>${items}</ul></div>`;
};

const renderTracks = (tracks: Mp4Track[]): string => {
  if (!tracks || tracks.length === 0) return "<p>No tracks parsed.</p>";
  const rows = tracks
    .map((track, index) => {
      const codecLabel = describeTrackCodec(track);
      const duration = track.durationSeconds != null ? formatDuration(track.durationSeconds) : "Unknown";
      const samples =
        track.sampleCount != null
          ? `${track.sampleCount} sample${track.sampleCount === 1 ? "" : "s"}`
          : track.chunkCount != null
            ? `${track.chunkCount} chunk${track.chunkCount === 1 ? "" : "s"}`
            : "Unknown";
      const warnings = renderTrackWarnings(track, index);
      return (
        "<tr>" +
        `<td>${escapeHtml(track.id ?? index + 1)}</td>` +
        `<td>${escapeHtml(track.kind)}</td>` +
        `<td>${escapeHtml(codecLabel)}</td>` +
        `<td>${escapeHtml(describeTrackDetails(track))}</td>` +
        `<td>${escapeHtml(duration)}</td>` +
        `<td>${escapeHtml(track.language || "-")}</td>` +
        `<td>${escapeHtml(samples)}</td>` +
        "</tr>" +
        (warnings ? `<tr class="dim"><td colspan="7">${warnings}</td></tr>` : "")
      );
    })
    .join("");
  return (
    "<h4>Tracks</h4>" +
    '<table class="table"><thead><tr>' +
    "<th>ID</th><th>Type</th><th>Codec</th><th>Details</th><th>Duration</th><th>Lang</th><th>Samples</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
};

const renderTopLevelBoxes = (boxes: Mp4ParseResult["topLevelBoxes"]): string => {
  if (!boxes || boxes.length === 0) return "";
  const rows = boxes
    .map(box => {
      const startHex = toHex32(box.start, 8);
      const sizeHex = toHex32(box.size, 8);
      const note = box.truncated ? "truncated" : "";
      return (
        "<tr>" +
        `<td>${escapeHtml(box.type)}</td>` +
        `<td>${escapeHtml(box.start)} (${startHex})</td>` +
        `<td>${escapeHtml(box.size)} (${sizeHex})</td>` +
        `<td>${escapeHtml(note)}</td>` +
        "</tr>"
      );
    })
    .join("");
  return (
    "<h4>Top-level boxes</h4>" +
    '<table class="byteView"><thead><tr><th>Type</th><th>Offset</th><th>Size</th><th>Note</th></tr></thead>' +
    `<tbody>${rows}</tbody></table>`
  );
};

export function renderMp4(mp4: Mp4ParseResult | null | unknown): string {
  const data = mp4 as Mp4ParseResult | null;
  if (!data) return "";
  const out: string[] = [];
  out.push("<h3>MP4 / ISO-BMFF container</h3>");
  const brandLabel = data.brands?.majorBrand
    ? `${data.brands.majorBrand}${data.brands.minorVersion != null ? ` (v${data.brands.minorVersion})` : ""}`
    : "Unknown";
  const compatible = data.brands?.compatibleBrands?.length
    ? data.brands.compatibleBrands.join(", ")
    : "None";
  out.push("<dl>");
  out.push(renderDefinitionRow("Major brand", escapeHtml(brandLabel)));
  out.push(renderDefinitionRow("Compatible brands", escapeHtml(compatible)));
  out.push(renderDefinitionRow("Duration", escapeHtml(formatDuration(data.movieHeader?.durationSeconds ?? null))));
  out.push(
    renderDefinitionRow(
      "Timescale",
      data.movieHeader?.timescale != null ? escapeHtml(`${data.movieHeader.timescale} ticks/s`) : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Fast start",
      data.fastStart === true ? "Yes" : data.fastStart === false ? "No (moov after mdat)" : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Fragments",
      data.fragmentCount ? escapeHtml(`${data.fragmentCount} moof box${data.fragmentCount === 1 ? "" : "es"}`) : "None"
    )
  );
  out.push(
    renderDefinitionRow(
      "Media data (mdat)",
      data.mdatBytes ? escapeHtml(formatHumanSize(data.mdatBytes)) : "Unknown size"
    )
  );
  out.push(renderDefinitionRow("Tracks parsed", escapeHtml(`${data.tracks.length}`)));
  out.push("</dl>");
  out.push(renderTracks(data.tracks));
  out.push(renderTopLevelBoxes(data.topLevelBoxes));
  out.push(renderIssues(data.warnings));
  return out.join("");
}
