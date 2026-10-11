import { escapeHtml } from "../html-utils.js";

const literalText = (value: string): string => escapeHtml(value.replaceAll("&", "&amp;"));

export const renderSymbolName = (raw: string, display: string): string =>
  raw === display ? literalText(raw) :
    `<code>${literalText(display)}</code><br><code class="dim">${literalText(raw)}</code>`;
