"use strict";

import { escapeHtml } from "../../html-utils.js";
import type { WebmTagEntry } from "../../analyzers/webm/types.js";

export const renderTagsSection = (tags: WebmTagEntry[] | null | undefined): string => {
  if (!tags || tags.length === 0) return "";
  const rows = tags
    .map((tag, index) => {
      const target = tag.targetTrackUid != null ? String(tag.targetTrackUid) : "-";
      const defaultFlag =
        tag.defaultFlag == null ? "default" : tag.defaultFlag ? "true" : "false";
      const binary = tag.binarySize != null ? `${tag.binarySize} B` : "-";
      const truncated = tag.truncated ? " (truncated)" : "";
      const value = tag.value ?? binary;
      return (
        "<tr>" +
        `<td>${index + 1}</td>` +
        `<td>${escapeHtml(tag.name ?? "-")}</td>` +
        `<td>${escapeHtml(value)}</td>` +
        `<td>${escapeHtml(tag.language ?? "-")}</td>` +
        `<td>${escapeHtml(target)}</td>` +
        `<td>${escapeHtml(defaultFlag + truncated)}</td>` +
        "</tr>"
      );
    })
    .join("");
  return (
    "<h4>Tags</h4>" +
    '<table class="byteView"><thead><tr><th>#</th><th>Name</th><th>Value/Binary</th><th>Lang</th><th>TrackUID</th><th>Default</th></tr></thead>' +
    `<tbody>${rows}</tbody></table>`
  );
};
