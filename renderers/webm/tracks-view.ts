"use strict";

import { escapeHtml } from "../../html-utils.js";
import type { WebmTrack } from "../../analyzers/webm/types.js";

const VIDEO_CODEC_OPTIONS = [
  ["V_VP8", "VP8"],
  ["V_VP9", "VP9"],
  ["V_AV1", "AV1"]
] as const;

const AUDIO_CODEC_OPTIONS = [
  ["A_VORBIS", "Vorbis"],
  ["A_OPUS", "Opus"]
] as const;

const greatestCommonDivisor = (left: number, right: number): number => {
  let a = Math.abs(left);
  let b = Math.abs(right);
  while (b !== 0) {
    const next = a % b;
    a = b;
    b = next;
  }
  return a === 0 ? 1 : a;
};

const describeSampleAspectRatio = (track: WebmTrack): string | null => {
  const pixelWidth = track.video?.pixelWidth ?? null;
  const pixelHeight = track.video?.pixelHeight ?? null;
  const displayWidth = track.video?.displayWidth ?? null;
  const displayHeight = track.video?.displayHeight ?? null;
  if (
    pixelWidth == null ||
    pixelHeight == null ||
    displayWidth == null ||
    displayHeight == null ||
    pixelWidth <= 0 ||
    pixelHeight <= 0 ||
    displayWidth <= 0 ||
    displayHeight <= 0
  ) {
    return null;
  }
  const sarNumerator = displayWidth * pixelHeight;
  const sarDenominator = displayHeight * pixelWidth;
  if (!Number.isFinite(sarNumerator) || !Number.isFinite(sarDenominator)) return null;
  const divisor = greatestCommonDivisor(sarNumerator, sarDenominator);
  return `${Math.floor(sarNumerator / divisor)}:${Math.floor(sarDenominator / divisor)}`;
};

const describeBitstreamFrameSizes = (track: WebmTrack): string | null => {
  const stats = track.bitstreamFrameStats;
  if (!stats) return null;
  const parts: string[] = [];
  parts.push(`Bitstream blocks ${stats.blockCount}, keyframes ${stats.keyframeCount}`);
  if (stats.parsedFrameCount > 0) {
    const range =
      stats.minWidth != null &&
      stats.maxWidth != null &&
      stats.minHeight != null &&
      stats.maxHeight != null
        ? `${stats.minWidth}x${stats.minHeight}..${stats.maxWidth}x${stats.maxHeight}`
        : "unknown";
    parts.push(`Bitstream sizes ${stats.uniqueSizes.length} unique (range ${range})`);
    if (stats.mismatchWithTrackEntryCount > 0) {
      parts.push(`TrackEntry mismatch in ${stats.mismatchWithTrackEntryCount}/${stats.parsedFrameCount}`);
    }
    if (stats.allBlocksAreKeyframes === true) parts.push("All blocks marked keyframe");
  }
  return parts.join(", ");
};

const describeTrackDetails = (track: WebmTrack): string => {
  const parts: string[] = [];
  if (track.video) {
    if (track.video.pixelWidth && track.video.pixelHeight) {
      parts.push(`Pixel ${track.video.pixelWidth} x ${track.video.pixelHeight}`);
    }
    if (track.video.displayWidth && track.video.displayHeight) {
      parts.push(`Display ${track.video.displayWidth} x ${track.video.displayHeight}`);
    }
    const sar = describeSampleAspectRatio(track);
    if (sar) parts.push(`SAR ${sar}`);
    if (track.defaultDurationFps) parts.push(`${track.defaultDurationFps} fps`);
    const bitstreamSummary = describeBitstreamFrameSizes(track);
    if (bitstreamSummary) parts.push(bitstreamSummary);
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

const renderFlagState = (value: boolean | null | undefined, defaultValue: boolean): string => {
  if (value === true) return "true";
  if (value === false) return "false";
  const defLabel = defaultValue ? "true" : "false";
  return `not set -> ${defLabel}`;
};

const renderCodecChips = (track: WebmTrack): string => {
  const codecId = track.codecId || "";
  const options =
    track.trackType === 1
      ? VIDEO_CODEC_OPTIONS
      : track.trackType === 2
        ? AUDIO_CODEC_OPTIONS
        : [...VIDEO_CODEC_OPTIONS, ...AUDIO_CODEC_OPTIONS];
  const chips = options.map(([id, label]) => {
    const isSelected = codecId === id;
    const tooltip = `${label} (${id})`;
    return `<span class="opt ${isSelected ? "sel" : "dim"}" title="${escapeHtml(tooltip)}">${escapeHtml(label)}</span>`;
  });
  if (codecId && !options.some(([id]) => id === codecId)) {
    const tooltip = track.codecIdValidForWebm === false ? "Not allowed in WebM" : "Codec not in WebM list";
    chips.push(
      `<span class="opt sel" title="${escapeHtml(tooltip)}">${escapeHtml(codecId)}</span>`
    );
  } else if (!codecId) {
    chips.push('<span class="opt dim" title="Codec not set">Unknown</span>');
  }
  return `<div class="optionsRow">${chips.join("")}</div>`;
};

const renderFlagsColumn = (track: WebmTrack): string => {
  const lines = [
    `FlagEnabled: ${renderFlagState(track.flagEnabled, true)}`,
    `FlagDefault: ${renderFlagState(track.flagDefault, true)}`,
    `FlagForced: ${renderFlagState(track.flagForced, false)}`,
    `FlagLacing: ${renderFlagState(track.flagLacing, true)}`
  ];
  const htmlLines = lines.map(line => escapeHtml(line)).join("<br />");
  return `<div class="flagColumn">${htmlLines}</div>`;
};

const renderCodecPrivate = (track: WebmTrack): string => {
  if (track.codecPrivateSize == null) return "-";
  const base = `${track.codecPrivateSize} B`;
  const vorbis = track.codecPrivateVorbis;
  if (!vorbis) return base;
  const parts: string[] = [];
  parts.push("Vorbis");
  if (vorbis.headerPacketLengths) {
    parts.push(
      `packets ${vorbis.headerPacketLengths[0]}/${vorbis.headerPacketLengths[1]}/${vorbis.headerPacketLengths[2]} B`
    );
  }
  if (vorbis.vendor) {
    parts.push(`vendor "${vorbis.vendor}"`);
  }
  if (vorbis.truncated) {
    parts.push("truncated");
  }
  return `${base} (${parts.join(", ")})`;
};

export const renderTracks = (tracks: WebmTrack[] | null | undefined): string => {
  if (!tracks || tracks.length === 0) return "<p>No tracks parsed.</p>";
  const rows = tracks
    .map((track, index) => {
      const number = track.trackNumber != null ? track.trackNumber : index + 1;
      const uid = track.trackUid != null ? String(track.trackUid) : "-";
      const codecPrivate = renderCodecPrivate(track);
      return (
        "<tr>" +
        `<td>${number}</td>` +
        `<td>${escapeHtml(track.trackTypeLabel)}</td>` +
        `<td>${renderCodecChips(track)}</td>` +
        `<td>${escapeHtml(uid)}</td>` +
        `<td>${renderFlagsColumn(track)}</td>` +
        `<td>${escapeHtml(describeTrackDetails(track))}</td>` +
        `<td>${escapeHtml(codecPrivate)}</td>` +
        "</tr>"
      );
    })
    .join("");
  return (
    "<h4>Tracks</h4>" +
    '<table class="table"><thead><tr>' +
    "<th>#</th><th>Type</th><th>Codec</th><th>UID</th><th>Flags</th><th>Details</th><th>CodecPrivate</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
};
