"use strict";

import { safe } from "../../html-utils.js";

export const renderPeSectionStart = (title: string, summary?: string): string =>
  `<section class="peSection"><details class="peSectionDetails">` +
  `<summary class="peSectionSummary"><b>${safe(title)}</b>${
    summary ? ` - ${safe(summary)}` : ""
  }</summary><div class="peSectionBody">`;

export const renderPeSectionEnd = (): string => "</div></details></section>";
