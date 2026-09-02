"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type { PeNativeAotAnalysis } from "../../analyzers/pe/native-aot.js";
import {
  nativeAotSectionName,
  type PeNativeAotMetadata
} from "../../analyzers/pe/native-aot/format.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

const renderMetadataSections = (metadata: PeNativeAotMetadata): string => {
  const rows = metadata.sections.map(section =>
    `<tr><td>${section.type}</td><td>${escapeHtml(nativeAotSectionName(section.type))}</td>` +
    `<td class="num">${hex(section.rva, 8)}</td>` +
    `<td class="num">${section.size == null ? "-" : humanSize(section.size)}</td></tr>`
  ).join("");
  return `<div class="tableScroll"><table><thead><tr><th>Type</th><th>Name</th>` +
    `<th class="num">RVA</th><th class="num">Size</th></tr></thead>` +
    `<tbody>${rows}</tbody></table></div>`;
};

const renderConfirmedMetadata = (metadata: PeNativeAotMetadata, out: string[]): void => {
  out.push(renderPeSectionStart("NativeAOT metadata", `${metadata.sections.length} sections`));
  out.push(`<p class="smallNote">Confirmed from a relocation-backed NativeAOT ReadyToRun ` +
    `header and the NativeFormat reflection-metadata signature.</p><dl>`);
  out.push(renderDefinitionRow("Layout", escapeHtml(metadata.layout)));
  out.push(renderDefinitionRow("Header", hex(metadata.headerRva, 8),
    `Referenced by relocated pointer at ${hex(metadata.modulePointerRva, 8)}.`));
  out.push(renderDefinitionRow("Version", `${metadata.majorVersion}.${metadata.minorVersion}`));
  out.push(`</dl><h4>ReadyToRun sections</h4>${renderMetadataSections(metadata)}`);
  out.push(renderPeSectionEnd());
};

export const renderNativeAot = (
  candidate: PeNativeAotAnalysis | null | undefined,
  out: string[]
): void => {
  if (!candidate) return;
  if (candidate.status === "confirmed") {
    renderConfirmedMetadata(candidate, out);
    return;
  }
  out.push(renderPeSectionStart("Native AOT candidate", "conservative evidence"));
  out.push(`<p class="smallNote">${escapeHtml(candidate.note)}</p>`);
  out.push(`<ul class="smallNote">`);
  candidate.evidence.forEach(item => out.push(`<li>${escapeHtml(item)}</li>`));
  out.push(`</ul>`);
  out.push(renderPeSectionEnd());
};

export const renderNativeAotCandidate = renderNativeAot;
