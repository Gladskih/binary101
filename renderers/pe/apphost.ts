"use strict";

import { hex } from "../../binary-utils.js";
import { getPeAppHostSectionDescriptor } from "./apphost-section-descriptor.js";
import type {
  PeAppHostBundleHeader,
  PeAppHostBundleLocation
} from "../../analyzers/pe/apphost/types.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

// Display convention: at least eight hex digits to match the PE RVA columns;
// wider 64-bit bundle offsets keep every digit, rather than being truncated to 32 bits.
const formatBigHex = (value: bigint): string =>
  `${value < 0n ? "-" : ""}0x${(value < 0n ? -value : value).toString(16).padStart(8, "0")}`;

const renderLocation = (location: PeAppHostBundleLocation): string =>
  `${formatBigHex(location.offset)} + ${formatBigHex(location.size)}`;

const renderBundleHeader = (header: PeAppHostBundleHeader, out: string[]): void => {
  out.push("<h4>Single-file bundle header</h4><dl>");
  out.push(renderDefinitionRow("Version", `${header.majorVersion}.${header.minorVersion}`));
  out.push(renderDefinitionRow("Embedded files", String(header.embeddedFileCount)));
  out.push(renderDefinitionRow("Bundle ID", escapeHtml(header.bundleId ?? "invalid UTF-8")));
  if (header.depsJson) out.push(renderDefinitionRow("deps.json", renderLocation(header.depsJson)));
  if (header.runtimeConfigJson) {
    out.push(renderDefinitionRow("runtimeconfig.json", renderLocation(header.runtimeConfigJson)));
  }
  if (header.flags != null) out.push(renderDefinitionRow("Flags", formatBigHex(header.flags)));
  out.push("</dl>");
};

const markerLocation = (pe: PeWindowsParseResult, rva: number): string => {
  const fileOffset = pe.rvaToOff(rva);
  return `${hex(rva, 8)}${fileOffset == null ? "" : ` (file ${hex(fileOffset, 8)})`}`;
};

const renderLocators = (pe: PeWindowsParseResult, out: string[]): void => {
  out.push("<div class=\"tableWrap\"><table class=\"table\"><thead><tr>" +
    "<th scope=\"col\">Bundle locator</th><th scope=\"col\">Bundle header offset</th>" +
    "</tr></thead><tbody>");
  for (const locator of pe.appHost!.locators) {
    out.push(`<tr><td>${markerLocation(pe, locator.rva)}</td><td class="num">` +
      `${locator.bundleHeaderOffset == null ? "unavailable" : formatBigHex(locator.bundleHeaderOffset)}` +
      "</td></tr>");
  }
  out.push("</tbody></table></div>");
};

const renderBindings = (pe: PeWindowsParseResult, out: string[]): void => {
  if (!pe.appHost!.bindings.length) return;
  out.push("<div class=\"tableWrap\"><table class=\"table\"><thead><tr>" +
    "<th scope=\"col\">Managed binding candidate</th><th scope=\"col\">Location</th>" +
    "<th scope=\"col\">Interpretation</th></tr></thead><tbody>");
  for (const binding of pe.appHost!.bindings) {
    out.push(`<tr><td>${escapeHtml(binding.value)}</td><td>${markerLocation(pe, binding.rva)}</td>` +
      `<td>${binding.kind === "unbound-placeholder"
        ? "The SDK template has not been bound to a managed application."
        : "Candidate UTF-8 application path; the binding is not verified."}</td></tr>`);
  }
  out.push("</tbody></table></div>");
};

export const renderPeAppHost = (pe: PeWindowsParseResult, out: string[]): void => {
  const appHost = pe.appHost;
  if (!appHost) return;
  const bundleHeader = appHost.locators.find(locator => locator.bundleHeader)?.bundleHeader;
  out.push(renderPeSectionStart(".NET apphost", bundleHeader
    ? `single-file bundle v${bundleHeader.majorVersion}.${bundleHeader.minorVersion}`
    : getPeAppHostSectionDescriptor(appHost).summary));
  out.push("<p class=\"smallNote\">The native host starts a managed application. " +
    "Strings ending in .dll are binding candidates and may include unrelated data.</p>");
  renderLocators(pe, out);
  renderBindings(pe, out);
  for (const locator of appHost.locators) {
    if (!locator.bundleHeader) continue;
    out.push(`<p>Bundle locator ${markerLocation(pe, locator.rva)}</p>`);
    renderBundleHeader(locator.bundleHeader, out);
  }
  if (appHost.issues.length) {
    out.push("<h4>Structural warnings</h4><ul class=\"smallNote\">");
    appHost.issues.forEach(issue => out.push(`<li>${escapeHtml(issue)}</li>`));
    out.push("</ul>");
  }
  out.push(renderPeSectionEnd());
};
