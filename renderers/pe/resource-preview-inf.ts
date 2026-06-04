"use strict";

import type { ResourceInfPreview } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";

const renderInfEntry = (entry: ResourceInfPreview["sections"][number]["entries"][number]): string => {
  const key = entry.key == null ? "" : `<span class="mono">${escapeHtml(entry.key)}</span> = `;
  return `<li><span class="smallNote">line ${entry.line}</span> ${key}${escapeHtml(entry.value)}</li>`;
};

export const renderInfPreview = (infPreview: ResourceInfPreview | undefined): string => {
  if (!infPreview) return "";
  const rows = infPreview.sections
    .map(section =>
      `<tr><td class="mono">${escapeHtml(section.name)}</td><td>${section.entries.length}</td>` +
      `<td><ul class="smallNote" style="padding-left:1.1rem;margin:0">` +
      `${section.entries.map(renderInfEntry).join("")}</ul></td></tr>`
    )
    .join("");
  return `<table class="table peResourceNestedTable peResourceTextTable">` +
    `<thead><tr><th>Section</th><th>Entries</th><th>Content</th></tr></thead>` +
    `<tbody>${rows}</tbody></table>`;
};
