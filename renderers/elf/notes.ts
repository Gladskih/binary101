"use strict";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import type { PagedSortableTableModel } from "../../ui/paged-sortable-table-state.js";
import { renderElfGnuProperties } from "./gnu-properties.js";
import { renderElfCoreNotes } from "./core-notes.js";

import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";
import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import type { ElfNoteEntry, ElfNotesInfo, ElfParseResult } from "../../analyzers/elf/types.js";
import { gnuBuildAttributeTypes } from "../../analyzers/elf/build-attribute-note.js";

const findFirst = (entries: ElfNoteEntry[], predicate: (entry: ElfNoteEntry) => boolean): ElfNoteEntry | null => {
  for (const entry of entries) {
    if (predicate(entry)) return entry;
  }
  return null;
};

const noteValues = (entry: ElfNoteEntry): string[] => [
  entry.source, entry.name, noteTypeName(entry),
  entry.description ?? "—", entry.value ?? "—", String(entry.descSize)
];

function noteTypeName(entry: ElfNoteEntry): string {
  if (entry.kind === "gnu-build-attribute") {
    return gnuBuildAttributeTypes[entry.type] ?? `0x${entry.type.toString(16)}`;
  }
  return entry.typeName ?? `0x${entry.type.toString(16)}`;
}

function visibleText(value: string): string {
  return Array.from(value, character => {
    const code = character.charCodeAt(0);
    return code < 32 || (code >= 127 && code <= 159)
      ? `\\x${code.toString(16).padStart(2, "0")}` : character;
  }).join("");
}

export const createElfNotesTableModel = (notes: ElfNotesInfo): PagedSortableTableModel => ({
  id: "elf-notes", pageSize: 100, rowCount: notes.entries.length,
  columns: ["Source", "Owner / attribute", "Type", "Description", "Value", "Descriptor bytes"]
    .map((label, index) => ({ label,
      className: index === 5 ? "peNumeric elfNote__value" : "elfNote__value" })),
  rowAt: index => {
    const entry = notes.entries[index];
    return entry ? { cells: noteValues(entry).map((value, column) => ({
      html: escapeHtml(visibleText(value)), sortValue: value,
      className: column === 5 ? "peNumeric" : "elfNote__value"
    })) } : null;
  },
  sortValueAt: (index, column) => notes.entries[index]
    ? noteValues(notes.entries[index]!)[column] ?? "" : ""
});

const renderIssues = (notes: ElfNotesInfo): string => {
  if (!notes.issues?.length) return "";
  const items = notes.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">Notes</summary><ul>${items}</ul></details>`;
};

export function renderElfNotes(elf: ElfParseResult, out: string[]): void {
  const notes = elf.notes;
  if (!notes) return;

  const buildId = findFirst(notes.entries, entry => entry.typeName === "NT_GNU_BUILD_ID" && entry.value != null);
  const abiTag = findFirst(notes.entries, entry => entry.typeName === "NT_GNU_ABI_TAG" && entry.value != null);

  out.push(renderElfSectionStart(`Notes`));
  out.push(`<div class="smallNote">Notes are small metadata blocks used for build IDs, ABI tags, platform features, and more.</div>`);
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Total notes", escapeHtml(String(notes.entries.length))));
  if (buildId) out.push(renderDefinitionRow("Build ID", `<span class="mono">${escapeHtml(buildId.value || "")}</span>`));
  if (abiTag) out.push(renderDefinitionRow("ABI tag", escapeHtml(abiTag.value || "")));
  out.push(`</dl>`);
  out.push(renderAutoPagedSortableTable(createElfNotesTableModel(notes)));
  renderElfGnuProperties(elf, out);
  renderElfCoreNotes(elf, out);
  out.push(renderIssues(notes));
  out.push(renderElfSectionEnd());
}
