"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import type {
  WebmAttachments,
  WebmComputedDuration,
  WebmCues,
  WebmParseResult,
  WebmSeekHead
} from "../../analyzers/webm/types.js";
import { renderTagsSection } from "./tags-view.js";
import { renderTracks } from "./tracks-view.js";

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

const formatComputedDuration = (computed: WebmComputedDuration | null | undefined): string | null => {
  if (!computed || computed.overallSeconds == null) return null;
  const overall = formatDuration(computed.overallSeconds);
  const video = computed.videoSeconds != null ? formatDuration(computed.videoSeconds) : null;
  const audio = computed.audioSeconds != null ? formatDuration(computed.audioSeconds) : null;
  if (!video && !audio) return overall;
  if (video && audio && video === audio) return overall;
  const parts: string[] = [];
  if (video) parts.push(`video ${video}`);
  if (audio) parts.push(`audio ${audio}`);
  return `${overall} (${parts.join("; ")})`;
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

const renderAttachments = (attachments: WebmAttachments | null | undefined): string => {
  if (!attachments || attachments.files.length === 0) return "";
  const rows = attachments.files
    .map((attached, index) => {
      const uid = attached.uid != null ? String(attached.uid) : "-";
      const size = attached.dataSize != null ? formatHumanSize(attached.dataSize) : "-";
      return (
        "<tr>" +
        `<td>${index + 1}</td>` +
        `<td>${escapeHtml(attached.fileName || "-")}</td>` +
        `<td>${escapeHtml(attached.mediaType || "-")}</td>` +
        `<td>${escapeHtml(uid)}</td>` +
        `<td>${escapeHtml(size)}</td>` +
        `<td>${escapeHtml(attached.description || "-")}</td>` +
        "</tr>"
      );
    })
    .join("");
  const truncated = attachments.truncated ? '<p class="dim">Attachments section truncated.</p>' : "";
  return (
    "<h4>Attachments</h4>" +
    '<table class="byteView"><thead><tr>' +
    "<th>#</th><th>Name</th><th>Type</th><th>UID</th><th>Size</th><th>Description</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>${truncated}`
  );
};

export function renderWebm(webm: WebmParseResult | null | unknown): string {
  const data = webm as WebmParseResult | null;
  if (!data) return "";
  const out: string[] = [];
  const containerTitle = data.isWebm
    ? "WebM container"
    : data.isMatroska
      ? "Matroska (MKV) container"
      : data.docType
        ? `Matroska (${data.docType}) container`
        : "Matroska/WebM container";
  out.push(`<h3>${escapeHtml(containerTitle)}</h3>`);
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
  const clusterDetails =
    segment?.clusterCount != null
      ? `${segment.clusterCount}${
          segment.firstClusterOffset != null
            ? ` (first @ ${segment.firstClusterOffset} / ${toHex32(segment.firstClusterOffset, 8)})`
            : ""
        }`
      : "Unknown";
  out.push(renderDefinitionRow("Clusters", escapeHtml(clusterDetails)));
  if (segment) {
    const blocksLabel =
      segment.blockCount || segment.keyframeCount
        ? `${segment.blockCount} (keyframes ${segment.keyframeCount})`
        : "Unknown";
    out.push(renderDefinitionRow("Blocks", escapeHtml(blocksLabel)));
  }
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
  const computedDuration = formatComputedDuration(segment?.computedDuration);
  if (computedDuration) {
    out.push(
      renderDefinitionRow(
        "Duration (computed)",
        escapeHtml(computedDuration),
        "Computed from Cluster/Block timestamps (uses BlockDuration/DefaultDuration when available)."
      )
    );
  }
  out.push(renderDefinitionRow("Title", escapeHtml(info?.title || "Not set")));
  out.push(renderDefinitionRow("Muxing app", escapeHtml(info?.muxingApp || "Unknown")));
  out.push(renderDefinitionRow("Writing app", escapeHtml(info?.writingApp || "Unknown")));
  out.push(renderDefinitionRow("Date UTC", escapeHtml(info?.dateUtc || "Unknown")));
  if (info?.segmentUid) {
    out.push(renderDefinitionRow("Segment UID", escapeHtml(info.segmentUid)));
  }
  out.push("</dl>");
  out.push(renderTracks(segment?.tracks));
  out.push(renderAttachments(segment?.attachments ?? null));
  out.push(renderTagsSection(segment?.tags ?? null));
  out.push(renderCues(segment?.cues));
  out.push(renderSeekHead(segment?.seekHead));
  out.push(renderIssues(data.issues));
  return out.join("");
}
