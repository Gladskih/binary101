"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { dd, rowFlags, safe } from "../../html-utils.js";
import type { PeClrHeader, PeClrManagedResourceValue } from "../../analyzers/pe/clr/index.js";
import type { ResourceLangWithPreview } from "../../analyzers/pe/resources/preview/types.js";
import { renderPreviewCell } from "./resource-preview-cell.js";

const formatClrDirectory = (rva: number, size: number): string =>
  rva || size ? `RVA ${hex(rva, 8)} Size ${humanSize(size)}` : "-";

const renderWarningList = (issues: string[]): string => {
  if (!issues.length) return "";
  const rows = issues.map(issue => `<li>${safe(issue)}</li>`).join("");
  return `<ul class="smallNote" style="color:var(--warn-fg)">${rows}</ul>`;
};

export const renderStrongName = (clrHeader: PeClrHeader, out: string[]): void => {
  const strongName = clrHeader.strongName;
  if (!strongName) return;
  out.push(`<details style="margin-top:.35rem" open><summary>Strong name</summary><dl>`);
  out.push(dd("Status", safe(strongName.status), "Strong-name signature directory state."));
  out.push(dd("Signature", formatClrDirectory(clrHeader.StrongNameSignatureRVA, clrHeader.StrongNameSignatureSize), "Signature blob location."));
  const publicKeySize = clrHeader.meta?.tables?.assembly?.publicKey?.length;
  out.push(dd("PublicKey", publicKeySize == null ? "-" : humanSize(publicKeySize), "Assembly public key blob size from CLR metadata."));
  out.push(dd("PublicKeyToken", strongName.publicKeyToken ? safe(strongName.publicKeyToken) : "-", "Last 8 bytes of SHA-1(public key), reversed."));
  out.push(dd("Verification", safe(strongName.verification), safe(strongName.verificationNote)));
  out.push(`</dl><div class="smallNote">Strong names identify assemblies and provide integrity metadata; they are not publisher trust and are separate from Authenticode certificates.</div>`);
  out.push(renderWarningList(strongName.issues));
  out.push(`</details>`);
};

const renderManagedResourceValue = (value: PeClrManagedResourceValue): string => {
  const preview = renderPreviewCell(value as unknown as ResourceLangWithPreview);
  return `<tr><td>${safe(value.name)}</td><td>${safe(value.type)}</td>` +
    `<td>${value.opaque ? "opaque" : safe(String(value.value ?? ""))}</td><td>${preview}</td></tr>`;
};

export const renderManagedResources = (clrHeader: PeClrHeader, out: string[]): void => {
  const resources = clrHeader.managedResources;
  if (!resources) return;
  out.push(`<details style="margin-top:.35rem" open><summary>Managed resources (${resources.entries.length})</summary>`);
  out.push(`<div class="smallNote">CLR managed resources are embedded through ManifestResource metadata and are separate from the PE .rsrc tree.</div>`);
  out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>Name</th><th>Storage</th><th>Offset</th><th>Size</th><th>Preview</th></tr></thead><tbody>`);
  resources.entries.forEach(entry => {
    const preview = renderPreviewCell(entry as unknown as ResourceLangWithPreview);
    out.push(`<tr><td>${safe(entry.name || "")}</td><td>${safe(entry.storage)}</td><td>${hex(entry.offset, 8)}</td><td>${entry.size == null ? "-" : humanSize(entry.size)}</td><td>${preview}</td></tr>`);
    if (entry.entries?.length) {
      out.push(`<tr><td colspan="5"><table class="table" style="margin:.25rem 0"><thead><tr><th>Entry</th><th>Type</th><th>Value</th><th>Preview</th></tr></thead><tbody>`);
      entry.entries.forEach(value => out.push(renderManagedResourceValue(value)));
      out.push(`</tbody></table></td></tr>`);
    }
    if (entry.issues?.length) out.push(`<tr><td colspan="5">${renderWarningList(entry.issues)}</td></tr>`);
  });
  out.push(`</tbody></table>${renderWarningList(resources.issues)}</details>`);
};

export const renderReadyToRun = (clrHeader: PeClrHeader, out: string[]): void => {
  const readyToRun = clrHeader.readyToRun;
  if (!readyToRun || readyToRun.status === "absent") return;
  out.push(`<details style="margin-top:.35rem" open><summary>ReadyToRun / managed native header</summary><dl>`);
  out.push(dd("Status", safe(readyToRun.status), "ReadyToRun means a managed IL assembly includes precompiled native code."));
  out.push(dd("Signature", readyToRun.signature == null ? "-" : hex(readyToRun.signature, 8), "Expected READYTORUN_SIGNATURE ('RTR')."));
  if (readyToRun.majorVersion != null && readyToRun.minorVersion != null) {
    out.push(dd("Version", `${readyToRun.majorVersion}.${readyToRun.minorVersion}`, "ReadyToRun major/minor version."));
  }
  if (readyToRun.flags != null) {
    // ReadyToRunCoreHeader flags come from CoreCLR readytorun.h:
    // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
    out.push(dd("Flags", `<div class="mono">${hex(readyToRun.flags, 8)}</div>${rowFlags(readyToRun.flags, [
      [0x00000001, "PLATFORM_NEUTRAL_SOURCE", "Original IL assembly was platform-neutral."],
      [0x00000010, "EMBEDDED_MSIL", "MSIL is embedded in a composite ReadyToRun image."],
      [0x00000100, "PLATFORM_NATIVE_IMAGE", "Owner composite executable uses platform-native format."],
      [0x00000200, "STRIPPED_IL_BODIES", "IL method bodies were stripped."],
      [0x00000400, "STRIPPED_INLINING_INFO", "Inlining info was stripped."],
      [0x00000800, "STRIPPED_DEBUG_INFO", "Debug info was stripped."]
    ])}`, "ReadyToRun core header flags."));
  }
  out.push(dd("Sections", `${readyToRun.sections.length} parsed / ${readyToRun.sectionCount} declared`, "ReadyToRun section table entries."));
  out.push(`</dl>`);
  if (readyToRun.sections.length) {
    out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>Type</th><th>Name</th><th>RVA</th><th>Size</th></tr></thead><tbody>`);
    readyToRun.sections.forEach(section => out.push(`<tr><td>${section.type}</td><td>${safe(section.name)}</td><td>${hex(section.rva, 8)}</td><td>${humanSize(section.size)}</td></tr>`));
    out.push(`</tbody></table>`);
  }
  out.push(`${renderWarningList(readyToRun.issues)}</details>`);
};
