import { escapeHtml } from "../../html-utils.js";

// Reuse the PE disclosure styles so both executable formats have the same presentation.
export const renderElfSectionStart = (title: string): string =>
  `<section class="peSection"><details class="peSectionDetails">` +
  `<summary class="peSectionSummary"><b>${escapeHtml(title)}</b></summary>` +
  `<div class="peSectionBody">`;

export const renderElfSectionEnd = (): string => "</div></details></section>";
