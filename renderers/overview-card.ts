import { escapeHtmlText } from "../html-utils.js";

export const overviewFact = (label: string, value: string): string =>
  `<span class="workspaceCard__fact"><span class="workspaceCard__label">` +
  `${escapeHtmlText(label)}</span><span class="workspaceCard__value">` +
  `${escapeHtmlText(value)}</span></span>`;

export const renderOverviewCard = (
  title: string, target: string, highlights: string, origin?: "supplemental"
): string => {
  if (!highlights) return "";
  const id = `card-${encodeURIComponent(target)}`;
  return `<button type="button" class="workspaceCard" ` +
    `data-workspace-target="${escapeHtmlText(target)}" aria-labelledby="${id}-title" ` +
    `aria-describedby="${id}-body"` +
    (origin ? ` data-analysis-origin="supplemental"` : "") + `>` +
    `<span class="workspaceCard__header"><span id="${id}-title">${escapeHtmlText(title)}</span>` +
    `<svg aria-hidden="true" viewBox="0 0 24 24"><path d="m9 5 7 7-7 7"/></svg></span>` +
    `<span class="workspaceCard__body" id="${id}-body">${highlights}</span></button>`;
};
