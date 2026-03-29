"use strict";

import { escapeHtml } from "../../html-utils.js";

export const renderIssues = (issues: string[] | null | undefined): string => {
  if (!issues || issues.length === 0) return "";

  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Issues</h4><ul class="issueList">${items}</ul>`;
};
