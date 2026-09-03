"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { nativeAotSectionName, type NativeAotMetadata } from
  "../../analyzers/native-aot/format.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import { renderNativeAotReflection } from "../native-aot/reflection.js";

const renderSections = (metadata: NativeAotMetadata): string => {
  const rows = metadata.sections.map(section =>
    `<tr><td class="nativeAotTable__compact">${section.type}</td>` +
    `<td>${escapeHtml(nativeAotSectionName(section.type))}</td>` +
    `<td class="nativeAotTable__compact peNumeric">${hex(section.rva, 8)}</td>` +
    `<td class="nativeAotTable__compact peNumeric">` +
    `${section.size == null ? "-" : humanSize(section.size)}</td></tr>`
  ).join("");
  return `<h4>ReadyToRun sections</h4>` +
    `<p class="smallNote">These entries locate NativeAOT runtime payloads in the loaded ELF ` +
    `image. The address is relative to the ELF load base. A dash means that the header names ` +
    `one address rather than a byte range.</p>` +
    `<div class="tableWrap"><table class="table nativeAotSectionsTable">` +
    `<thead><tr><th>Type</th><th>Name</th><th class="peNumeric">Image address</th>` +
    `<th class="peNumeric">Size</th></tr></thead><tbody>${rows}</tbody></table></div>`;
};

export const renderElfNativeAot = (elf: ElfParseResult, out: string[]): void => {
  const metadata = elf.nativeAot;
  if (!metadata) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">NativeAOT metadata</h4>`);
  out.push(`<p class="smallNote">NativeAOT compiled managed code into this ELF executable. ` +
    `Confirmation follows relative REL/RELA relocations to a ReadyToRun header and then checks ` +
    `the embedded NativeFormat signature; section names alone are not treated as proof.</p><dl>`);
  out.push(renderDefinitionRow(
    "Layout",
    escapeHtml(metadata.layout),
    "How each ReadyToRun directory entry stores its payload address and extent."
  ));
  out.push(renderDefinitionRow(
    "Header",
    hex(metadata.headerRva, 8),
    `Image-relative ReadyToRun header address. REL/RELA slot ${hex(metadata.modulePointerRva, 8)} ` +
    `refers to it.`
  ));
  out.push(renderDefinitionRow(
    "Version",
    `${metadata.majorVersion}.${metadata.minorVersion}`,
    "ReadyToRun format version, not the application or installed .NET version."
  ));
  out.push(`</dl>${renderSections(metadata)}`);
  if (metadata.reflection) out.push(renderNativeAotReflection(metadata.reflection));
  out.push(`</section>`);
};
