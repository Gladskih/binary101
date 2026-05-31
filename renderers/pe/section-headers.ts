"use strict";

import { escapeHtml } from "../../html-utils.js";
import { hex, humanSize } from "../../binary-utils.js";
import { formatSectionCharacteristicFlags } from "../../analyzers/pe/constants.js";
import { isPeWindowsParseResult, type PeParseResult } from "../../analyzers/pe/index.js";
import type { PeSection } from "../../analyzers/pe/types.js";
import { peSectionNameOffset, peSectionNameValue } from "../../analyzers/pe/sections/name.js";
import { knownSectionName } from "./header-format.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

const getRawTailSize = (section: PeSection): number =>
  Math.max(0, (section.sizeOfRawData >>> 0) - (section.virtualSize >>> 0));

const renderZeroFillStatus = (section: PeSection): string => {
  if (section.rawTail?.zeroFilled === true) return "zero-filled";
  if (section.rawTail?.zeroFilled === false) return "contains non-zero bytes";
  return "unknown zero-fill status";
};

const renderPaddingCell = (section: PeSection, fileAlignment: number | null): string => {
  const rawTailSize = getRawTailSize(section);
  if (!rawTailSize) return `<span class="dim">No</span>`;
  const alignmentStatus = fileAlignment == null
    ? "FileAlignment unavailable"
    : rawTailSize > fileAlignment
      ? `exceeds FileAlignment (${humanSize(fileAlignment)})`
      : `does not exceed FileAlignment (${humanSize(fileAlignment)})`;
  const readableStatus = section.rawTail && section.rawTail.readableSize !== rawTailSize
    ? `; readable ${humanSize(section.rawTail.readableSize)}`
    : "";
  const warnings = section.rawTail?.warnings?.length
    ? `<div class="smallNote" style="color:var(--warn-fg)">` +
      `${escapeHtml(section.rawTail.warnings.join("; "))}</div>`
    : "";
  return `${humanSize(rawTailSize)}` +
    `<div class="smallNote">${escapeHtml(renderZeroFillStatus(section))}${readableStatus}</div>` +
    `<div class="smallNote">${escapeHtml(alignmentStatus)}</div>${warnings}`;
};

export const renderSections = (pe: PeParseResult, out: string[]): void => {
  const sections = pe.sections || [];
  if (!sections.length) return;
  const fileAlignment = isPeWindowsParseResult(pe) && pe.opt.FileAlignment > 0
    ? pe.opt.FileAlignment >>> 0
    : null;
  const showCoffSectionTables = sections.some(section =>
    section.pointerToRelocations ||
    section.pointerToLinenumbers ||
    section.numberOfRelocations ||
    section.numberOfLinenumbers
  );
  out.push(renderPeSectionStart(
    "Section headers",
    `${sections.length} section${sections.length === 1 ? "" : "s"}`
  ));
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr>` +
    `<th>Name</th><th>VirtualSize</th><th>RVA</th><th>RawSize</th><th>FilePtr</th>` +
    (showCoffSectionTables ? `<th>RelocPtr</th><th>Relocs</th><th>LinePtr</th><th>Lines</th>` : "") +
    `<th>Padding</th><th>Entropy</th><th>Flags</th></tr></thead><tbody>`
  );
  sections.forEach(section => {
    const flags = formatSectionCharacteristicFlags(section.characteristics);
    const sectionName = peSectionNameValue(section.name);
    const coffStringTableOffset = peSectionNameOffset(section.name);
    const hint = knownSectionName(sectionName);
    const baseNameCell = hint
      ? `<span title="${hint}"><b>${escapeHtml(sectionName || "(unnamed)")}</b></span>`
      : `<span title="User-defined">${escapeHtml(sectionName || "(unnamed)")}</span>`;
    const nameCell =
      coffStringTableOffset != null && sectionName !== `/${coffStringTableOffset}`
        ? `${baseNameCell}<div class="smallNote dim">COFF name /${coffStringTableOffset}</div>`
        : baseNameCell;
    out.push(`<tr>
        <td>${nameCell}</td>
        <td>${humanSize(section.virtualSize)}</td>
        <td>${hex(section.virtualAddress, 8)}</td>
        <td>${humanSize(section.sizeOfRawData)}</td>
        <td>${hex(section.pointerToRawData, 8)}</td>
        ${showCoffSectionTables
          ? `<td>${hex(section.pointerToRelocations ?? 0, 8)}</td>` +
            `<td>${section.numberOfRelocations ?? 0}</td>` +
            `<td>${hex(section.pointerToLinenumbers ?? 0, 8)}</td>` +
            `<td>${section.numberOfLinenumbers ?? 0}</td>`
          : ""}
        <td>${renderPaddingCell(section, fileAlignment)}</td>
        <td title="Shannon entropy (0..8 bits/byte). Near 0 means very simple or empty, near 8 means very mixed data (often compressed or encrypted).">${(section.entropy ?? 0).toFixed(2)}</td>
        <td>${flags.join(" &middot; ")}</td>
      </tr>`);
  });
  out.push(`</tbody></table>`);
  out.push(renderPeSectionEnd());
};
