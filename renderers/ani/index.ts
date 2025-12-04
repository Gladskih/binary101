"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";
import { renderChunkTable } from "../riff/chunk-table.js";
import type { AniParseResult } from "../../analyzers/ani/types.js";

const renderIssues = (issues: string[] | null | undefined): string => {
  if (!issues || issues.length === 0) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
};

const renderInfoTags = (ani: AniParseResult): string => {
  if (!ani.infoTags || ani.infoTags.length === 0) return "";
  const rows = ani.infoTags
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

const renderArrayPreview = (label: string, values: number[]): string => {
  if (!values.length) return "";
  const preview = values.slice(0, 12).join(", ");
  const suffix = values.length > 12 ? " …" : "";
  return renderDefinitionRow(label, `${preview}${suffix}`);
};

export const renderAni = (ani: AniParseResult | null | unknown): string => {
  const data = ani as AniParseResult | null;
  if (!data) return "";
  const out: string[] = [];
  out.push("<h3>Animated cursor (ANI)</h3>");
  out.push("<dl>");
  out.push(
    renderDefinitionRow(
      "File size",
      escapeHtml(formatHumanSize(data.riff.fileSize))
    )
  );
  out.push(
    renderDefinitionRow(
      "Dimensions",
      data.header?.width && data.header.height
        ? `${data.header.width} x ${data.header.height}`
        : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Frames",
      data.header?.frameCount != null
        ? `${data.header.frameCount} declared, ${data.frames} chunk(s)`
        : `${data.frames} chunk(s)`
    )
  );
  if (data.header?.stepCount != null) {
    out.push(renderDefinitionRow("Steps", String(data.header.stepCount)));
  }
  out.push(
    renderDefinitionRow(
      "Default rate",
      data.header?.defaultFps ? `${data.header.defaultFps} fps` : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Flags",
      data.header?.flagNotes?.length
        ? escapeHtml(data.header.flagNotes.join(", "))
        : data.header?.flags != null
          ? `0x${data.header.flags.toString(16)}`
          : "None"
    )
  );
  out.push(renderArrayPreview("Per-frame rates (jiffies)", data.rates));
  out.push(renderArrayPreview("Sequence order", data.sequence));
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
