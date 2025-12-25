"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import type { MpegPsParseResult, MpegPsStreamSummary } from "../../analyzers/mpegps/types.js";

const renderIssues = (issues: string[] | null | undefined): string => {
  if (!issues || issues.length === 0) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Issues</h4><ul class="issueList">${items}</ul>`;
};

const formatDurationSeconds = (seconds: number | null | undefined): string => {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return "Unknown";
  if (seconds < 0.001) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 10) return `${Math.round(seconds * 1000) / 1000} s`;
  if (seconds < 600) return `${Math.round(seconds * 10) / 10} s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = Math.round(seconds - minutes * 60);
  return `${minutes} min ${remaining} s`;
};

const describeMuxRate = (muxRate: number | null): string => {
  if (muxRate == null) return "Unknown";
  const bytesPerSecond = muxRate * 50;
  const bitsPerSecond = bytesPerSecond * 8;
  const mbps = bitsPerSecond / 1_000_000;
  const rounded = Math.round(mbps * 100) / 100;
  return `${muxRate} (≈ ${rounded} Mbps)`;
};

const formatPtsSeconds = (pts90k: number | null | undefined): string => {
  if (typeof pts90k !== "number" || !Number.isFinite(pts90k) || pts90k < 0) return "-";
  return `${Math.round((pts90k / 90000) * 1000) / 1000} s`;
};

const describeStreamId = (streamId: number): string => {
  if (streamId >= 0xe0 && streamId <= 0xef) return "Video stream";
  if (streamId >= 0xc0 && streamId <= 0xdf) return "Audio stream";
  if (streamId === 0xbd) return "Private stream 1";
  if (streamId === 0xbe) return "Padding stream";
  if (streamId === 0xbf) return "Private stream 2";
  return "Stream";
};

const renderPesStreams = (streams: MpegPsStreamSummary[]): string => {
  if (!streams || streams.length === 0) return "<p>No PES streams were summarized.</p>";
  const rows = streams
    .map(stream => {
      const idHex = toHex32(stream.streamId, 2);
      const pts = stream.pts;
      const ptsRange =
        pts.count > 0 ? `${formatPtsSeconds(pts.min)} → ${formatPtsSeconds(pts.max)}` : "-";
      const duration = formatDurationSeconds(pts.durationSeconds);
      const note =
        stream.packetLengthZeroCount > 0
          ? `(${stream.packetLengthZeroCount} packets with unspecified length)`
          : "";
      return (
        "<tr>" +
        `<td>${escapeHtml(idHex)}</td>` +
        `<td>${escapeHtml(describeStreamId(stream.streamId))}</td>` +
        `<td>${escapeHtml(stream.kind)}</td>` +
        `<td>${escapeHtml(stream.packetCount)} ${escapeHtml(note)}</td>` +
        `<td>${escapeHtml(formatHumanSize(stream.declaredBytesTotal))}</td>` +
        `<td>${escapeHtml(`${pts.count}`)}</td>` +
        `<td>${escapeHtml(ptsRange)}</td>` +
        `<td>${escapeHtml(duration)}</td>` +
        "</tr>"
      );
    })
    .join("");
  return (
    "<h4>PES streams</h4>" +
    '<table class="table"><thead><tr>' +
    "<th>Stream ID</th><th>Name</th><th>Kind</th><th>Packets</th><th>Declared bytes</th><th>PTS</th><th>PTS range</th><th>Duration</th>" +
    `</tr></thead><tbody>${rows}</tbody></table>`
  );
};

const renderSystemHeader = (data: MpegPsParseResult): string => {
  const hdr = data.systemHeaders.firstHeader;
  if (!hdr) return "";
  const bounds = hdr.streamBounds;
  const rows = bounds
    .map(bound => {
      const idHex = toHex32(bound.streamId, 2);
      const size = bound.bufferSizeBytes != null ? formatHumanSize(bound.bufferSizeBytes) : "-";
      const scale = bound.scale != null ? `${bound.scale}` : "-";
      const raw = bound.sizeBound != null ? `${bound.sizeBound}` : "-";
      return `<tr><td>${escapeHtml(idHex)}</td><td>${escapeHtml(scale)}</td><td>${escapeHtml(raw)}</td><td>${escapeHtml(
        size
      )}</td></tr>`;
    })
    .join("");
  const table =
    bounds.length > 0
      ? "<h5>Stream buffer bounds</h5>" +
        '<table class="byteView"><thead><tr><th>Stream</th><th>Scale</th><th>Size bound</th><th>Buffer size</th></tr></thead>' +
        `<tbody>${rows}</tbody></table>`
      : "";
  return (
    "<h4>System header</h4>" +
    "<dl>" +
    renderDefinitionRow("Rate bound", hdr.rateBound != null ? escapeHtml(`${hdr.rateBound}`) : "Unknown") +
    renderDefinitionRow("Audio bound", hdr.audioBound != null ? escapeHtml(`${hdr.audioBound}`) : "Unknown") +
    renderDefinitionRow("Video bound", hdr.videoBound != null ? escapeHtml(`${hdr.videoBound}`) : "Unknown") +
    "</dl>" +
    table
  );
};

export function renderMpegPs(parsed: MpegPsParseResult | null | unknown): string {
  const data = parsed as MpegPsParseResult | null;
  if (!data) return "";
  const out: string[] = [];
  out.push("<h3>MPEG Program Stream (MPEG-PS)</h3>");

  out.push("<dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(data.fileSize))));
  out.push(renderDefinitionRow("Pack headers", escapeHtml(`${data.packHeaders.totalCount}`)));
  out.push(
    renderDefinitionRow(
      "Pack header variants",
      escapeHtml(
        `MPEG-2: ${data.packHeaders.mpeg2Count}, MPEG-1: ${data.packHeaders.mpeg1Count}, unknown: ${data.packHeaders.invalidCount}`
      )
    )
  );
  out.push(renderDefinitionRow("Stuffing bytes", escapeHtml(`${data.packHeaders.stuffingBytesTotal}`)));
  out.push(renderDefinitionRow("System headers", escapeHtml(`${data.systemHeaders.totalCount}`)));
  out.push(renderDefinitionRow("Program Stream Maps", escapeHtml(`${data.programStreamMaps.totalCount}`)));
  out.push(renderDefinitionRow("PES packets", escapeHtml(`${data.pes.totalPackets}`)));
  out.push(
    renderDefinitionRow(
      "Declared PES bytes",
      data.pes.totalDeclaredBytes ? escapeHtml(formatHumanSize(data.pes.totalDeclaredBytes)) : "Unknown"
    )
  );
  if (data.programEndCodeOffset != null) {
    out.push(
      renderDefinitionRow("Program end code", escapeHtml(`${data.programEndCodeOffset} (${toHex32(data.programEndCodeOffset, 8)})`))
    );
  }
  const muxMin = data.packHeaders.muxRate.min;
  const muxMax = data.packHeaders.muxRate.max;
  out.push(
    renderDefinitionRow(
      "Program mux rate",
      muxMin != null && muxMax != null && muxMin !== muxMax
        ? escapeHtml(`${describeMuxRate(muxMin)} → ${describeMuxRate(muxMax)}`)
        : escapeHtml(describeMuxRate(muxMin ?? muxMax ?? null))
    )
  );
  out.push("</dl>");

  out.push(renderSystemHeader(data));
  out.push(renderPesStreams(data.pes.streams));

  if (data.programStreamMaps.totalCount > 0) {
    const typeRows = data.programStreamMaps.streamTypes
      .map(type => `<tr><td>${escapeHtml(toHex32(type.streamType, 2))}</td><td>${escapeHtml(`${type.count}`)}</td></tr>`)
      .join("");
    if (typeRows) {
      out.push("<h4>Stream types (from Program Stream Maps)</h4>");
      out.push('<table class="byteView"><thead><tr><th>Stream type</th><th>Entries</th></tr></thead><tbody>');
      out.push(typeRows);
      out.push("</tbody></table>");
    }
  }

  out.push(renderIssues(data.issues));
  return out.join("");
}

