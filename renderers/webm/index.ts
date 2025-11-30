"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import type { WebmCues, WebmParseResult, WebmSeekHead, WebmTrack } from "../../analyzers/webm/types.js";

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

const describeTrackDetails = (track: WebmTrack): string => {
  const parts: string[] = [];
  if (track.video) {
    const width = track.video.displayWidth || track.video.pixelWidth;
    const height = track.video.displayHeight || track.video.pixelHeight;
    if (width && height) parts.push(`${width} x ${height}`);
    if (track.defaultDurationFps) parts.push(`${track.defaultDurationFps} fps`);
  }
  if (track.audio) {
    if (track.audio.samplingFrequency) parts.push(`${Math.round(track.audio.samplingFrequency)} Hz`);
    if (track.audio.channels) parts.push(`${track.audio.channels} channel(s)`);
    if (track.audio.bitDepth) parts.push(`${track.audio.bitDepth}-bit`);
  }
  if (track.language) parts.push(`lang: ${track.language}`);
  if (track.name) parts.push(`title: ${track.name}`);
  return parts.length ? parts.join(", ") : "No details";
};

const renderTrackFlags = (track: WebmTrack): string => {
  const flags: string[] = [];
  if (track.flagEnabled != null) flags.push(track.flagEnabled ? "Enabled" : "Disabled");
  if (track.flagDefault != null) flags.push(track.flagDefault ? "Default" : "Not default");
  if (track.flagForced === true) flags.push("Forced");
  if (track.flagLacing === false) flags.push("No lacing");
  if (track.codecPrivateSize != null) flags.push(`CodecPrivate: ${track.codecPrivateSize} B`);
  return flags.length ? flags.join(", ") : "None noted";
};

const renderTracks = (tracks: WebmTrack[] | null | undefined): string => {
  if (!tracks || tracks.length === 0) return "<p>No tracks parsed.</p>";
  const rows = tracks
    .map((track, index) => {
      const number = track.trackNumber != null ? track.trackNumber : index + 1;
      const uid = track.trackUid != null ? String(track.trackUid) : "-";
      const codec = escapeHtml(track.codecId || track.codecName || "Unknown");
      return (
        "<tr>" +
        `<td>${number}</td>` +
        `<td>${escapeHtml(track.trackTypeLabel)}</td>` +
        `<td>${codec}</td>` +
        `<td>${escapeHtml(describeTrackDetails(track))}</td>` +
        `<td>${escapeHtml(renderTrackFlags(track))}<br /><span class="dim">UID: ${escapeHtml(uid)}</span></td>` +
        "</tr>"
      );
    })
    .join("");
  return (
    "<h4>Tracks</h4>" +
    '<table class="byteView"><thead><tr>' +
    "<th>#</th><th>Type</th><th>Codec</th><th>Details</th><th>Flags</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
};

const renderSeekHead = (seekHead: WebmSeekHead | null | undefined): string => {
  if (!seekHead || !seekHead.entries || seekHead.entries.length === 0) return "";
  const rows = seekHead.entries
    .map(entry => {
      const offset =
        entry.absoluteOffset != null
          ? `${entry.absoluteOffset} (${toHex32(entry.absoluteOffset, 8)})`
          : "-";
      const relative = entry.position != null ? String(entry.position) : "-";
      return (
        "<tr>" +
        `<td>${escapeHtml(entry.name || `0x${entry.id.toString(16)}`)}</td>` +
        `<td>${relative}</td>` +
        `<td>${escapeHtml(offset)}</td>` +
        "</tr>"
      );
    })
    .join("");
  return (
    "<h4>Seek head</h4>" +
    '<table class="byteView"><thead><tr>' +
    "<th>Target</th><th>Position (relative)</th><th>Absolute offset</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
};

const renderCues = (cues: WebmCues | null | undefined): string => {
  if (!cues || cues.cuePoints.length === 0) return "";
  const rows = cues.cuePoints
    .map((cue, index) => {
      const time =
        cue.timecodeSeconds != null
          ? `${cue.timecodeSeconds} s`
          : cue.timecode != null
            ? String(cue.timecode)
            : "-";
      const positions = cue.positions
        .map(position => {
          const track = position.track != null ? `Track ${position.track}` : "Track ?";
          const cluster = position.clusterPosition != null ? `@ ${position.clusterPosition}` : "@ -";
          return `${track} ${cluster}`;
        })
        .join("; ");
      return (
        "<tr>" +
        `<td>${index + 1}</td>` +
        `<td>${escapeHtml(time)}</td>` +
        `<td>${escapeHtml(positions || "-")}</td>` +
        "</tr>"
      );
    })
    .join("");
  const truncated = cues.truncated ? '<p class="dim">Cues section truncated.</p>' : "";
  return (
    "<h4>Cues</h4>" +
    '<table class="byteView"><thead><tr><th>#</th><th>Time</th><th>Positions</th></tr></thead>' +
    `<tbody>${rows}</tbody></table>${truncated}`
  );
};

export function renderWebm(webm: WebmParseResult | null | unknown): string {
  const data = webm as WebmParseResult | null;
  if (!data) return "";
  const out: string[] = [];
  out.push("<h3>WebM / Matroska container</h3>");
  const segment = data.segment;
  const info = segment?.info || null;
  out.push("<dl>");
  out.push(renderDefinitionRow("DocType", escapeHtml(data.docType || "Unknown")));
  out.push(
    renderDefinitionRow(
      "EBML version",
      escapeHtml(
        data.ebmlHeader.ebmlVersion != null
          ? `${data.ebmlHeader.ebmlVersion} (read ${data.ebmlHeader.ebmlReadVersion ?? "-"})`
          : "Unknown"
      )
    )
  );
  out.push(
    renderDefinitionRow(
      "DocType version",
      escapeHtml(
        data.ebmlHeader.docTypeVersion != null
          ? `${data.ebmlHeader.docTypeVersion} (read ${data.ebmlHeader.docTypeReadVersion ?? "-"})`
          : "Unknown"
      )
    )
  );
  out.push(
    renderDefinitionRow(
      "Segment size",
      segment?.size != null ? escapeHtml(formatHumanSize(segment.size)) : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Timecode scale",
      info?.timecodeScale != null ? `${info.timecodeScale} ns` : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Duration",
      escapeHtml(formatDuration(info?.durationSeconds ?? null)),
      "Duration is reported in timecode units scaled by TimecodeScale."
    )
  );
  out.push(renderDefinitionRow("Title", escapeHtml(info?.title || "Not set")));
  out.push(renderDefinitionRow("Muxing app", escapeHtml(info?.muxingApp || "Unknown")));
  out.push(renderDefinitionRow("Writing app", escapeHtml(info?.writingApp || "Unknown")));
  out.push(renderDefinitionRow("Date UTC", escapeHtml(info?.dateUtc || "Unknown")));
  if (info?.segmentUid) {
    out.push(renderDefinitionRow("Segment UID", escapeHtml(info.segmentUid)));
  }
  out.push("</dl>");
  out.push(renderTracks(segment?.tracks));
  out.push(renderCues(segment?.cues));
  out.push(renderSeekHead(segment?.seekHead));
  out.push(renderIssues(data.issues));
  return out.join("");
}
