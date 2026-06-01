"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { renderDefinitionRow, renderFlagChips, escapeHtml } from "../../html-utils.js";
import type { PeClrHeader, PeClrManagedResourceValue } from "../../analyzers/pe/clr/index.js";
import type { PeClrManagedResourceEntry } from "../../analyzers/pe/clr/managed-resource-types.js";
import type { PeClrMetadataIndex } from "../../analyzers/pe/clr/types.js";
import type { ResourceLangWithPreview } from "../../analyzers/pe/resources/preview/types.js";
import { renderPreviewCell } from "./resource-preview-cell.js";

const formatClrDirectory = (rva: number, size: number): string =>
  rva || size ? `RVA ${hex(rva, 8)} Size ${humanSize(size)}` : "-";

const indexText = (index: PeClrMetadataIndex): string =>
  index.row === 0 ? "-" : `${index.table} #${index.row}${index.valid ? "" : " (invalid)"}`;

const renderWarningList = (issues: string[]): string => {
  if (!issues.length) return "";
  const rows = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<ul class="smallNote" style="color:var(--warn-fg)">${rows}</ul>`;
};

export const renderStrongName = (clrHeader: PeClrHeader, out: string[]): void => {
  const strongName = clrHeader.strongName;
  if (!strongName) return;
  out.push(`<details style="margin-top:.35rem" open><summary>Strong name</summary><dl>`);
  out.push(renderDefinitionRow("Status", escapeHtml(strongName.status), "Strong-name signature directory state."));
  out.push(renderDefinitionRow("Signature", formatClrDirectory(clrHeader.StrongNameSignatureRVA, clrHeader.StrongNameSignatureSize), "Signature blob location."));
  const publicKeySize = clrHeader.meta?.tables?.assembly?.publicKey?.length;
  out.push(renderDefinitionRow("PublicKey", publicKeySize == null ? "-" : humanSize(publicKeySize), "Assembly public key blob size from CLR metadata."));
  out.push(renderDefinitionRow("PublicKeyToken", strongName.publicKeyToken ? escapeHtml(strongName.publicKeyToken) : "-", "Last 8 bytes of SHA-1(public key), reversed."));
  out.push(renderDefinitionRow("Verification", escapeHtml(strongName.verification), escapeHtml(strongName.verificationNote)));
  out.push(`</dl><div class="smallNote">Strong names identify assemblies and provide integrity metadata; they are not publisher trust and are separate from Authenticode certificates.</div>`);
  out.push(renderWarningList(strongName.issues));
  out.push(`</details>`);
};

const hasManagedResourcePreview = (entry: PeClrManagedResourceEntry): boolean =>
  Boolean(entry.previewKind || entry.previewFields?.length || entry.previewDataUrl || entry.textPreview);

const renderManagedResourceMetadata = (entry: PeClrManagedResourceEntry): string =>
  `<dl class="clrManagedResourceMeta">` +
    renderDefinitionRow("Storage", escapeHtml(entry.storage)) +
    renderDefinitionRow("Offset", hex(entry.offset, 8)) +
    renderDefinitionRow("Flags", hex(entry.flags, 8)) +
    renderDefinitionRow("Implementation", escapeHtml(indexText(entry.implementation))) +
    renderDefinitionRow("Size", entry.size == null ? "-" : humanSize(entry.size)) +
  `</dl>`;

const hasVisiblePreview = (previewHtml: string): boolean => {
  if (/<(?:img|audio)\b/i.test(previewHtml)) return true;
  const textOnly = previewHtml.replace(/[<>]/g, "").trim();
  return textOnly !== "" && previewHtml.trim() !== "-";
};

const renderManagedResourceValues = (values: PeClrManagedResourceValue[]): string => {
  const tableClass = values.every(value => value.type === "String")
    ? "table clrManagedResourceValuesTable clrManagedResourceStringsTable"
    : "table clrManagedResourceValuesTable";
  const rows = values.map(value => {
    const previewHtml = renderPreviewCell(value as unknown as ResourceLangWithPreview);
    const preview = hasVisiblePreview(previewHtml)
      ? `<tr class="clrManagedResourceValuePreviewRow"><td colspan="3">` +
        `${previewHtml}</td></tr>`
      : "";
    return `<tr><td>${escapeHtml(value.name)}</td><td>${escapeHtml(value.type)}</td>` +
      `<td>${value.opaque ? "opaque" : escapeHtml(String(value.value ?? ""))}</td></tr>${preview}`;
  }).join("");
  return `<table class="${tableClass}">` +
    `<thead><tr><th>Entry</th><th>Type</th><th>Value</th></tr></thead>` +
    `<tbody>${rows}</tbody></table>`;
};

const renderManagedResourceEntry = (entry: PeClrManagedResourceEntry): string => {
  const preview = hasManagedResourcePreview(entry)
    ? `<div class="clrManagedResourcePreview">${renderPreviewCell(entry as unknown as ResourceLangWithPreview)}</div>`
    : "";
  const values = entry.entries?.length
    ? `<div class="clrManagedResourceValues">${renderManagedResourceValues(entry.entries)}</div>`
    : "";
  return `<section class="clrManagedResourceBlock">` +
    `<h4 class="clrManagedResourceTitle">${escapeHtml(entry.name || "(unnamed resource)")}</h4>` +
    `<div class="clrManagedResourceSummary">${renderManagedResourceMetadata(entry)}${preview}</div>` +
    `${values}${entry.issues?.length ? renderWarningList(entry.issues) : ""}</section>`;
};

export const renderManagedResources = (clrHeader: PeClrHeader, out: string[]): void => {
  const resources = clrHeader.managedResources;
  if (!resources) return;
  out.push(`<details style="margin-top:.35rem" open><summary>Managed resources (${resources.entries.length})</summary>`);
  out.push(`<div class="smallNote">CLR ManifestResource rows with embedded payload details; separate from the PE .rsrc tree.</div>`);
  out.push(`<div class="clrManagedResourceList">`);
  resources.entries.forEach(entry => out.push(renderManagedResourceEntry(entry)));
  out.push(`</div>${renderWarningList(resources.issues)}</details>`);
};

export const renderReadyToRun = (clrHeader: PeClrHeader, out: string[]): void => {
  const readyToRun = clrHeader.readyToRun;
  if (!readyToRun || readyToRun.status === "absent") return;
  out.push(`<details style="margin-top:.35rem" open><summary>ReadyToRun / managed native header</summary><dl>`);
  out.push(renderDefinitionRow("Status", escapeHtml(readyToRun.status), "ManagedNativeHeader format classification."));
  out.push(renderDefinitionRow("Signature", readyToRun.signature == null ? "-" : hex(readyToRun.signature, 8), "ManagedNativeHeader signature."));
  if (readyToRun.status === "ready-to-run") {
    if (readyToRun.majorVersion != null && readyToRun.minorVersion != null) {
      out.push(renderDefinitionRow("Version", `${readyToRun.majorVersion}.${readyToRun.minorVersion}`, "ReadyToRun major/minor version."));
    }
    if (readyToRun.flags != null) {
      // ReadyToRunCoreHeader flags come from CoreCLR readytorun.h:
      // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
      out.push(renderDefinitionRow("Flags", `<div class="mono">${hex(readyToRun.flags, 8)}</div>${renderFlagChips(readyToRun.flags, [
        [0x00000001, "PLATFORM_NEUTRAL_SOURCE", "Original IL assembly was platform-neutral."],
        [0x00000010, "EMBEDDED_MSIL", "MSIL is embedded in a composite ReadyToRun image."],
        [0x00000100, "PLATFORM_NATIVE_IMAGE", "Owner composite executable uses platform-native format."],
        [0x00000200, "STRIPPED_IL_BODIES", "IL method bodies were stripped."],
        [0x00000400, "STRIPPED_INLINING_INFO", "Inlining info was stripped."],
        [0x00000800, "STRIPPED_DEBUG_INFO", "Debug info was stripped."]
      ])}`, "ReadyToRun core header flags."));
    }
    out.push(renderDefinitionRow("Sections", `${readyToRun.sections.length} parsed / ${readyToRun.sectionCount} declared`, "ReadyToRun section table entries."));
  }
  out.push(`</dl>`);
  if (readyToRun.status === "ready-to-run" && readyToRun.sections.length) {
    out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>Type</th><th>Name</th><th>RVA</th><th>Size</th></tr></thead><tbody>`);
    readyToRun.sections.forEach(section => out.push(`<tr><td>${section.type}</td><td>${escapeHtml(section.name)}</td><td>${hex(section.rva, 8)}</td><td>${humanSize(section.size)}</td></tr>`));
    out.push(`</tbody></table>`);
  }
  out.push(`${renderWarningList(readyToRun.issues)}</details>`);
};
