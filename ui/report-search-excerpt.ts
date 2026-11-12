import { escapeHtmlText } from "../html-utils.js";
import { reportTextPattern } from "./report-text-search.js";

export const renderSearchExcerpt = (value: string, query: string): string => {
  const pattern = reportTextPattern(query);
  // Keep the first match and nearby context visible without rendering entire resources.
  const offset = Math.max(0, (pattern ? value.search(pattern) : 0) - 60);
  const extent = Math.max(360, query.trim().length + 60);
  const excerpt = value.slice(offset, offset + extent);
  const parts: string[] = [];
  let cursor = 0;
  if (pattern) {
    for (const match of excerpt.matchAll(new RegExp(pattern, "giu"))) {
      parts.push(escapeHtmlText(excerpt.slice(cursor, match.index)),
        `<mark>${escapeHtmlText(match[0])}</mark>`);
      cursor = match.index + match[0].length;
    }
  }
  parts.push(escapeHtmlText(excerpt.slice(cursor)));
  return (offset ? "…" : "") + parts.join("") + (offset + extent < value.length ? "…" : "");
};
