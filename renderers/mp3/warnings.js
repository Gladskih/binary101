"use strict";

import { escapeHtml } from "../../html-utils.js";

export function renderWarnings(issues) {
  if (!issues || issues.length === 0) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
}
