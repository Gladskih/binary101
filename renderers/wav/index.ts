"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";
import { renderChunkTable } from "../riff/chunk-table.js";
import type { WavParseResult } from "../../analyzers/wav/types.js";

const renderIssues = (issues: string[] | null | undefined): string => {
  if (!issues || issues.length === 0) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
};

const describeCodec = (wav: WavParseResult): string => {
  if (wav.format?.formatName) return wav.format.formatName;
  if (wav.format?.audioFormat != null) {
    return `Format tag 0x${wav.format.audioFormat.toString(16)}`;
  }
  return "Unknown format";
};

const describeDuration = (wav: WavParseResult): string => {
  const duration = wav.data?.durationSeconds;
  if (duration == null) return "Unknown";
  return `${duration} s`;
};

const describeBits = (wav: WavParseResult): string => {
  if (wav.format?.bitsPerSample) return `${wav.format.bitsPerSample} bits`;
  if (wav.format?.validBitsPerSample) {
    return `${wav.format.validBitsPerSample} valid bits`;
  }
  return "Unknown";
};

const renderInfoTags = (wav: WavParseResult): string => {
  if (!wav.infoTags || wav.infoTags.length === 0) return "";
  const rows = wav.infoTags
    .map(tag => {
      const note = tag.truncated ? " class=\"dim\"" : "";
      return `<tr${note}><td>${escapeHtml(tag.id)}</td><td>${escapeHtml(tag.value)}</td></tr>`;
    })
    .join("");
  return (
    "<h4>INFO metadata</h4>" +
    '<table class="byteView"><thead><tr><th>Tag</th><th>Value</th></tr></thead>' +
    `<tbody>${rows}</tbody></table>`
  );
};

export const renderWav = (wav: WavParseResult | null | unknown): string => {
  const data = wav as WavParseResult | null;
  if (!data) return "";
  const out: string[] = [];
  out.push("<h3>WAVE audio</h3>");
  out.push("<dl>");
  out.push(
    renderDefinitionRow(
      "File size",
      escapeHtml(formatHumanSize(data.riff.fileSize))
    )
  );
  out.push(renderDefinitionRow("Codec", escapeHtml(describeCodec(data))));
  out.push(
    renderDefinitionRow(
      "Channels",
      data.format?.channels != null ? String(data.format.channels) : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Sample rate",
      data.format?.sampleRate ? `${data.format.sampleRate} Hz` : "Unknown"
    )
  );
  out.push(renderDefinitionRow("Bit depth", escapeHtml(describeBits(data))));
  out.push(
    renderDefinitionRow(
      "Duration",
      escapeHtml(describeDuration(data)),
      "Derived from data chunk size and byte rate."
    )
  );
  if (data.factSampleLength != null) {
    out.push(
      renderDefinitionRow(
        "Fact sample length",
        `${data.factSampleLength} samples`,
        "Reported for compressed WAVE formats."
      )
    );
  }
  if (data.data) {
    out.push(
      renderDefinitionRow(
        "Data chunk",
        `${formatHumanSize(data.data.size)} at offset ${data.data.offset}`
      )
    );
  }
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
  out.push(renderInfoTags(data));
  out.push(renderChunkTable(data.riff.chunks));
  return out.join("");
};
