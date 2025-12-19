"use strict";

import { dd, safe } from "../../html-utils.js";
import type { ElfNoteEntry, ElfNotesInfo, ElfParseResult } from "../../analyzers/elf/types.js";

const findFirst = (entries: ElfNoteEntry[], predicate: (entry: ElfNoteEntry) => boolean): ElfNoteEntry | null => {
  for (const entry of entries) {
    if (predicate(entry)) return entry;
  }
  return null;
};

const renderNotesTable = (notes: ElfNotesInfo): string => {
  if (!notes.entries.length) return `<div class="smallNote dim">No note entries parsed.</div>`;
  const limit = 2000;
  const slice = notes.entries.slice(0, limit);
  const truncated = notes.entries.length > limit;
  const summary = truncated ? `Show notes (${limit} of ${notes.entries.length})` : `Show notes (${notes.entries.length})`;

  const rows = slice
    .map(entry => {
      const src = safe(entry.source);
      const name = safe(entry.name || "");
      const typeLabel = entry.typeName ? safe(entry.typeName) : safe(`0x${entry.type.toString(16)}`);
      const desc = entry.description ? safe(entry.description) : "<span class=\"dim\">-</span>";
      const value = entry.value ? safe(entry.value) : "<span class=\"dim\">-</span>";
      const size = safe(String(entry.descSize));
      return `<tr><td>${src}</td><td>${name}</td><td>${typeLabel}</td><td>${desc}</td><td>${value}</td><td>${size}</td></tr>`;
    })
    .join("");

  return (
    `<details style="margin-top:.35rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">${safe(
      summary
    )}</summary>` +
      `<div class="tableWrap"><table class="table" style="margin-top:.35rem"><thead><tr>` +
      `<th>Source</th><th>Name</th><th>Type</th><th>Description</th><th>Value</th><th>DescSz</th>` +
      `</tr></thead><tbody>${rows}</tbody></table></div></details>`
  );
};

const renderIssues = (notes: ElfNotesInfo): string => {
  if (!notes.issues?.length) return "";
  const items = notes.issues.map(issue => `<li>${safe(issue)}</li>`).join("");
  return `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">Notes</summary><ul>${items}</ul></details>`;
};

export function renderElfNotes(elf: ElfParseResult, out: string[]): void {
  const notes = elf.notes;
  if (!notes) return;

  const buildId = findFirst(notes.entries, entry => entry.typeName === "NT_GNU_BUILD_ID" && entry.value != null);
  const abiTag = findFirst(notes.entries, entry => entry.typeName === "NT_GNU_ABI_TAG" && entry.value != null);

  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notes</h4>`);
  out.push(`<div class="smallNote">Notes are small metadata blocks used for build IDs, ABI tags, platform features, and more.</div>`);
  out.push(`<dl>`);
  out.push(dd("Total notes", safe(String(notes.entries.length))));
  if (buildId) out.push(dd("Build ID", `<span class="mono">${safe(buildId.value || "")}</span>`));
  if (abiTag) out.push(dd("ABI tag", safe(abiTag.value || "")));
  out.push(`</dl>`);
  out.push(renderNotesTable(notes));
  out.push(renderIssues(notes));
  out.push(`</section>`);
}

