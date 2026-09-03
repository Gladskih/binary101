"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type { PeNativeAotAnalysis } from "../../analyzers/pe/native-aot.js";
import {
  nativeAotSectionName,
  type NativeAotMetadata
} from "../../analyzers/native-aot/format.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { renderNativeAotReflection } from "../native-aot/reflection.js";

const renderMetadataSections = (metadata: NativeAotMetadata): string => {
  const rows = metadata.sections.map(section =>
    `<tr><td class="nativeAotTable__compact">${section.type}</td>` +
    `<td>${escapeHtml(nativeAotSectionName(section.type))}</td>` +
    `<td class="nativeAotTable__compact peNumeric">${hex(section.rva, 8)}</td>` +
    `<td class="nativeAotTable__compact peNumeric">` +
    `${section.size == null ? "-" : humanSize(section.size)}</td></tr>`
  ).join("");
  return `<p class="smallNote">Each row is an internal NativeAOT runtime payload. ` +
    `RVA is its address relative to the loaded image. A dash for Size means the header names ` +
    `one address rather than a byte range; generic blob names are IDs without a stable ` +
    `description in this analyzer.</p>` +
    `<div class="tableWrap"><table class="table nativeAotSectionsTable">` +
    `<thead><tr><th>Type</th><th>Name</th>` +
    `<th class="peNumeric">RVA</th><th class="peNumeric">Size</th></tr></thead>` +
    `<tbody>${rows}</tbody></table></div>`;
};

const renderConfirmedMetadata = (metadata: NativeAotMetadata, out: string[]): void => {
  out.push(renderPeSectionStart("NativeAOT metadata", `${metadata.sections.length} sections`));
  out.push(`<p class="smallNote">NativeAOT turns managed code into native machine code before ` +
    `deployment. This is the runtime directory and the reflection information retained in the ` +
    `native image; it is not the usual CLR metadata table from an IL assembly. Confirmation ` +
    `requires a relocation-backed ReadyToRun header and NativeFormat signature; names alone are ` +
    `not accepted as evidence.</p><dl>`);
  out.push(renderDefinitionRow(
    "Layout",
    escapeHtml(metadata.layout),
    "How each ReadyToRun directory entry stores its payload address and extent."
  ));
  out.push(renderDefinitionRow("Header", hex(metadata.headerRva, 8),
    `Image-relative address of the ReadyToRun header. A relocated module pointer at ` +
    `${hex(metadata.modulePointerRva, 8)} refers to it.`));
  out.push(renderDefinitionRow(
    "Version",
    `${metadata.majorVersion}.${metadata.minorVersion}`,
    "ReadyToRun header format version, not the application or installed .NET version."
  ));
  out.push(`</dl><h4>ReadyToRun sections</h4>${renderMetadataSections(metadata)}`);
  if (metadata.reflection) out.push(renderNativeAotReflection(metadata.reflection));
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
