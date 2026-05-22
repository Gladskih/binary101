"use strict";

import { escapeHtml } from "../html-utils.js";

type DownloadButtonAttribute = readonly [name: string, value?: number | string];

const renderAttribute = ([name, value]: DownloadButtonAttribute): string =>
  value == null ? ` ${name}` : ` ${name}="${escapeHtml(String(value))}"`;

export const renderDownloadButton = (
  label: string,
  attributes: readonly DownloadButtonAttribute[]
): string =>
  `<button type="button" class="downloadIconButton"` +
  `${attributes.map(renderAttribute).join("")} aria-label="${escapeHtml(label)}" ` +
  `title="${escapeHtml(label)}">` +
  `<svg aria-hidden="true" viewBox="0 0 16 16" width="14" height="14" fill="none" ` +
  `stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">` +
  `<path d="M8 2.5v7"></path><path d="M5 6.8 8 9.8l3-3"></path>` +
  `<path d="M3 12.5h10"></path>` +
  `</svg></button>`;
