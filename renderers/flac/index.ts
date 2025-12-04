"use strict";

import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type {
  FlacApplicationBlock,
  FlacCueSheetBlock,
  FlacMetadataBlockDetail,
  FlacParseResult,
  FlacPictureBlock,
  FlacSeekPoint,
  FlacSeekTableBlock,
  FlacStreamInfo,
  FlacVorbisCommentBlock
} from "../../analyzers/flac/types.js";

const formatMaybe = (value: number | null | undefined, suffix = ""): string =>
  value == null ? "Unknown" : `${value}${suffix}`;

const formatBig = (value: bigint | number | null | undefined): string => {
  if (value == null) return "Unknown";
  return typeof value === "bigint" ? value.toString() : String(value);
};

const renderWarnings = (warnings: string[]): string => {
  if (!warnings.length) return "";
  const items = warnings.map(w => `<li>${escapeHtml(w)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
};

const renderSummary = (info: FlacStreamInfo | null, audioBytes: number | null): string => {
  const out: string[] = [];
  out.push("<h4>Summary</h4><dl>");
  out.push(renderDefinitionRow("Channels", formatMaybe(info?.channels, "ch")));
  out.push(renderDefinitionRow("Sample rate", formatMaybe(info?.sampleRate, " Hz")));
  out.push(renderDefinitionRow("Bit depth", formatMaybe(info?.bitsPerSample, "-bit")));
  out.push(renderDefinitionRow("Duration", formatMaybe(info?.durationSeconds, " s")));
  out.push(renderDefinitionRow("Average bitrate", formatMaybe(info?.averageBitrateKbps, " kbps")));
  out.push(renderDefinitionRow("Total samples", formatMaybe(info?.totalSamples, "")));
  out.push(
    renderDefinitionRow(
      "Block size",
      `${formatMaybe(info?.minBlockSize)} min / ${formatMaybe(info?.maxBlockSize)} max`
    )
  );
  out.push(
    renderDefinitionRow(
      "Frame size",
      `${formatMaybe(info?.minFrameSize)} min / ${formatMaybe(info?.maxFrameSize)} max`
    )
  );
  out.push(renderDefinitionRow("Stream MD5", info?.md5 ? escapeHtml(info.md5) : "Unknown"));
  if (audioBytes != null) out.push(renderDefinitionRow("Audio data", formatHumanSize(audioBytes)));
  out.push("</dl>");
  return out.join("");
};

const blockNote = (block: FlacMetadataBlockDetail): string => {
  if (block.truncated) return "Truncated";
  if (block.type === "STREAMINFO") return "Stream info";
  if (block.type === "VORBIS_COMMENT") return `${block.comments.length} comments`;
  if (block.type === "SEEKTABLE") return `${block.points.length} seekpoints`;
  if (block.type === "PICTURE") return block.mimeType || "Picture";
  if (block.type === "APPLICATION") return block.id || "Application block";
  if (block.type === "CUESHEET") return "Cue sheet";
  if (block.type === "PADDING") return "Padding";
  return "";
};

const renderBlockTable = (blocks: FlacMetadataBlockDetail[]): string => {
  if (!blocks.length) return "";
  const rows = blocks
    .map(block => {
      const note = blockNote(block);
      const noteHtml = note ? escapeHtml(note) : "&nbsp;";
      const flags = `${block.isLast ? "last" : ""}${block.truncated ? " truncated" : ""}`.trim();
      const flagHtml = flags ? escapeHtml(flags) : "—";
      return [
        "<tr>",
        `<td>${escapeHtml(block.type)}</td>`,
        `<td>${toHex32(block.rawType)}</td>`,
        `<td>${block.length}</td>`,
        `<td>${block.offset}</td>`,
        `<td>${flagHtml}</td>`,
        `<td>${noteHtml}</td>`,
        "</tr>"
      ].join("");
    })
    .join("");
  return [
    "<h4>Metadata blocks</h4>",
    [
      '<table class="byteView"><thead><tr><th>Type</th><th>Raw</th><th>Length</th>',
      "<th>Offset</th><th>Flags</th><th>Notes</th></tr></thead>"
    ].join(""),
    `<tbody>${rows}</tbody></table>`
  ].join("");
};

const renderComments = (block: FlacVorbisCommentBlock | null): string => {
  if (!block || (!block.vendor && !block.comments.length)) return "";
  const vendor = block.vendor ? escapeHtml(block.vendor) : "Unknown";
  const commentRows = block.comments
    .map(comment => {
      const key = escapeHtml(comment.key || "(empty)");
      return `<tr><td>${key}</td><td>${escapeHtml(comment.value)}</td></tr>`;
    })
    .join("");
  const commentTable = block.comments.length
    ? [
        '<table class="byteView"><thead><tr><th>Key</th><th>Value</th></tr></thead>',
        `<tbody>${commentRows}</tbody></table>`
      ].join("")
    : "<p class=\"dim\">No comments.</p>";
  return `<h4>Vorbis comments</h4><p>Vendor: ${vendor}</p>${commentTable}`;
};

const formatPoint = (point: FlacSeekPoint): string => {
  const base = [
    formatBig(point.sampleNumber),
    "@",
    formatBig(point.streamOffset),
    `(+${formatMaybe(point.frameSamples)})`
  ].join(" ");
  return point.placeholder ? `${base} placeholder` : base;
};

const renderSeekTable = (block: FlacSeekTableBlock | null): string => {
  if (!block || !block.points.length) return "";
  const items = block.points
    .slice(0, 12)
    .map(point => `<li>${escapeHtml(formatPoint(point))}</li>`)
    .join("");
  const suffix =
    block.points.length > 12
      ? `<p class="dim">Showing 12 of ${block.points.length} points.</p>`
      : "";
  return `<h4>Seek table</h4><ul class="issueList">${items}</ul>${suffix}`;
};

const pictureLabel = (pictureType: number | null): string => {
  if (pictureType == null) return "Unknown";
  const labels: Record<number, string> = {
    0: "Other",
    1: "32x32 icon",
    2: "Other icon",
    3: "Front cover",
    4: "Back cover",
    5: "Leaflet",
    6: "Media",
    7: "Lead artist",
    8: "Artist",
    9: "Conductor",
    10: "Band",
    11: "Composer",
    12: "Lyricist",
    13: "Recording location",
    14: "During recording",
    15: "During performance",
    16: "Video",
    17: "Fish",
    18: "Illustration",
    19: "Band logotype",
    20: "Publisher logotype"
  };
  return labels[pictureType] || `Type ${pictureType}`;
};

const renderPictures = (blocks: FlacPictureBlock[]): string => {
  if (!blocks.length) return "";
  const rows = blocks
    .map(block => {
      const desc = block.description ? escapeHtml(block.description) : "—";
      const size =
        block.width && block.height ? `${block.width}x${block.height}` : "Unknown size";
      const dataSize = block.dataLength != null ? formatHumanSize(block.dataLength) : "Unknown";
      return `<tr><td>${escapeHtml(pictureLabel(block.pictureType))}</td><td>${escapeHtml(
        block.mimeType || "Unknown"
      )}</td><td>${size}</td><td>${escapeHtml(desc)}</td><td>${dataSize}</td></tr>`;
    })
    .join("");
  return [
    "<h4>Pictures</h4>",
    [
      '<table class="byteView"><thead><tr><th>Type</th><th>MIME</th><th>Dimensions</th>',
      "<th>Description</th><th>Data size</th></tr></thead>"
    ].join(""),
    `<tbody>${rows}</tbody></table>`
  ].join("");
};

const renderApplications = (blocks: FlacApplicationBlock[]): string => {
  if (!blocks.length) return "";
  const rows = blocks
    .map(
      block =>
        `<tr><td>${escapeHtml(block.id || "Unknown")}</td><td>${block.dataLength ?? 0}</td></tr>`
    )
    .join("");
  return [
    "<h4>Applications</h4>",
    '<table class="byteView"><thead><tr><th>ID</th><th>Data length</th></tr></thead>',
    `<tbody>${rows}</tbody></table>`
  ].join("");
};

const renderCuesheets = (blocks: FlacCueSheetBlock[]): string => {
  if (!blocks.length) return "";
  const rows = blocks
    .map(block => {
      const catalog = block.catalog ? escapeHtml(block.catalog) : "—";
      const leadIn = formatBig(block.leadInSamples);
      const cdFlag = block.isCd == null ? "Unknown" : block.isCd ? "CD" : "Data";
      const tracks = block.trackCount == null ? "Unknown" : String(block.trackCount);
      return `<tr><td>${catalog}</td><td>${leadIn}</td><td>${cdFlag}</td><td>${tracks}</td></tr>`;
    })
    .join("");
  return [
    "<h4>Cue sheets</h4>",
    [
      '<table class="byteView"><thead><tr><th>Catalog</th><th>Lead-in</th>',
      "<th>Type</th><th>Tracks</th></tr></thead>"
    ].join(""),
    `<tbody>${rows}</tbody></table>`
  ].join("");
};

const renderFlac = (input: FlacParseResult | null | unknown): string => {
  const flac = input as FlacParseResult | null;
  if (!flac) return "";
  const blocks = flac.blocks || [];
  const vorbis = blocks.find(b => b.type === "VORBIS_COMMENT") as
    | FlacVorbisCommentBlock
    | undefined;
  const seek = blocks.find(b => b.type === "SEEKTABLE") as FlacSeekTableBlock | undefined;
  const pictures = blocks.filter(b => b.type === "PICTURE") as FlacPictureBlock[];
  const applications = blocks.filter(b => b.type === "APPLICATION") as FlacApplicationBlock[];
  const cuesheets = blocks.filter(b => b.type === "CUESHEET") as FlacCueSheetBlock[];

  const out: string[] = [];
  out.push("<h3>FLAC audio</h3>");
  out.push(renderSummary(flac.streamInfo, flac.audioDataBytes));
  out.push(renderBlockTable(blocks));
  out.push(renderComments(vorbis || null));
  out.push(renderSeekTable(seek || null));
  out.push(renderPictures(pictures));
  out.push(renderApplications(applications));
  out.push(renderCuesheets(cuesheets));
  out.push(renderWarnings(flac.warnings || []));
  return out.join("");
};

export { renderFlac };
