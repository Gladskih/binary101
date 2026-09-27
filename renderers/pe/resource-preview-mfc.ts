"use strict";

import type { ResourcePreviewData } from "../../analyzers/pe/resources/preview/types.js";
import { escapeHtml } from "../../html-utils.js";

const describeMessage = (message: number): string => {
  // CWnd::ExecuteDlgInit translates the Win16 messages, not the current Win32 values.
  // https://gist.github.com/thinkhy/794742
  const names = new Map([[0x401, "LB_ADDSTRING (Win16)"], [0x403, "CB_ADDSTRING (Win16)"],
    [0x1234, "AFX_CB_ADDSTRING / CBEM_INSERTITEM"]]);
  return `0x${message.toString(16).padStart(4, "0")}${names.has(message) ? ` (${names.get(message)})` : ""}`;
};

const renderPayload = (message: number, data: Uint8Array): string => {
  if (message === 0x401 || message === 0x403) {
    const end = data.indexOf(0);
    return escapeHtml(new TextDecoder("windows-1252").decode(data.subarray(0, end < 0 ? data.length : end)));
  }
  return Array.from(data.subarray(0, 32), byte => byte.toString(16).padStart(2, "0"))
    .join(" ") + (data.length > 32 ? " …" : "");
};

export const renderDialogInitPreview = (init: NonNullable<ResourcePreviewData["dialogInit"]>): string =>
  `<p class="smallNote">MFC DLGINIT. ADDSTRING text is displayed as Windows-1252; ` +
  `the resource does not declare its ANSI code page.</p>` +
  `<div style="overflow-x:auto"><table class="table peResourceNestedTable"><thead><tr>` +
  `<th>Control ID</th><th>Message</th><th>Bytes</th><th>Text / data</th></tr></thead><tbody>` +
  init.entries.map(entry => `<tr><td class="mono peNumeric">${entry.controlId}</td>` +
    `<td>${escapeHtml(describeMessage(entry.message))}</td><td class="peNumeric">${entry.data.length}</td>` +
    `<td>${renderPayload(entry.message, entry.data)}</td></tr>`).join("") + `</tbody></table></div>`;

export const renderToolbarPreview = (toolbar: NonNullable<ResourcePreviewData["toolbar"]>): string =>
  `<p>MFC toolbar v${toolbar.version}; ${toolbar.width}×${toolbar.height} pixel images.</p>` +
  `<table class="table peResourceNestedTable"><thead><tr><th>Position</th><th>Command</th></tr></thead>` +
  `<tbody>${toolbar.items.map((id, index) => `<tr><td class="peNumeric">${index + 1}</td>` +
    `<td class="mono">${id ? `#${id}` : "Separator"}</td></tr>`).join("")}</tbody></table>`;
