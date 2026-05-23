"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import { getDebugTypeInfo } from "./debug-type-info.js";
import {
  getDebugStorageInfo,
  getEntrySummary
} from "./debug-entry-summary.js";
import {
  renderDecodedEntryDetails
} from "./debug-payload-details.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

const formatEntryType = (entry: PeDebugDirectoryEntry): string => {
  const typeInfo = getDebugTypeInfo(entry.type >>> 0);
  return `${escapeHtml(typeInfo.label)}<div class="valueHint">${hex(entry.type, 8)}</div>`;
};

const renderEntryTable = (pe: PeWindowsParseResult, out: string[]): void => {
  if (!pe.debug?.entries?.length) return;
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr>` +
      `<th>#</th><th>Type</th><th>Storage</th><th>Payload</th>` +
      `<th>Raw RVA</th><th>Raw file ptr</th><th>What it contains</th></tr></thead><tbody>`
  );
  pe.debug.entries.forEach((entry, index) => {
    const storageInfo = getDebugStorageInfo(pe, entry);
    out.push(
      `<tr><td>${index + 1}</td><td>${formatEntryType(entry)}</td>` +
        `<td title="${escapeHtml(storageInfo.description)}">${escapeHtml(storageInfo.label)}</td>` +
        `<td>${humanSize(entry.sizeOfData)}</td><td>${hex(entry.addressOfRawData, 8)}</td>` +
        `<td>${hex(entry.pointerToRawData, 8)}</td>` +
        `<td>${escapeHtml(getEntrySummary(entry))}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
};

const renderDebugIntro = (out: string[]): void => {
  out.push(
    `<div class="smallNote">IMAGE_DEBUG_DIRECTORY is an index of debug payloads. Each entry says ` +
      `what format is present, how large it is, and where the payload lives in the file. ` +
      `Storage tells you whether the payload is mapped through a section or only exists in raw file layout.</div>`
  );
};

export function renderDebug(pe: PeWindowsParseResult, out: string[]): void {
  if (!pe.debug) return;
  out.push(
    renderPeSectionStart(
      "Debug directory",
      `${pe.debug.entries?.length ?? 0} entr${(pe.debug.entries?.length ?? 0) === 1 ? "y" : "ies"}`
    )
  );
  renderDebugIntro(out);
  renderEntryTable(pe, out);
  renderDecodedEntryDetails(pe, pe.debug, out);
  if (pe.debug.warning) out.push(`<div class="smallNote">${escapeHtml(pe.debug.warning)}</div>`);
  out.push(renderPeSectionEnd());
}
