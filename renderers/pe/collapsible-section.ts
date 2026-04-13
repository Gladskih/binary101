"use strict";

import { safe } from "../../html-utils.js";

const PE_SECTION_SUMMARY_STYLE = [
  "cursor:pointer",
  "padding:.35rem .6rem",
  "border:1px solid var(--border2)",
  "border-radius:8px",
  "background:var(--chip-bg)"
].join(";");

export const renderPeSectionStart = (title: string, summary?: string): string =>
  `<section><details><summary style="${PE_SECTION_SUMMARY_STYLE}"><b>${safe(title)}</b>${
    summary ? ` - ${safe(summary)}` : ""
  }</summary><div style="margin-top:.5rem">`;

export const renderPeSectionEnd = (): string => "</div></details></section>";
