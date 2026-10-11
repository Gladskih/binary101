"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { renderDefinitionRow, renderFlagChips, escapeHtml } from "../../html-utils.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/index.js";
import { renderReadyToRunData } from "./ready-to-run-tables.js";
import { renderPeSectionStart, renderPeSectionEnd } from "./collapsible-section.js";

const formatClrDirectory = (rva: number, size: number): string =>
  rva || size ? `RVA ${hex(rva, 8)} Size ${humanSize(size)}` : "-";

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

export const renderReadyToRun = (clrHeader: Pick<PeClrHeader, "readyToRun">, out: string[]): void => {
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
    out.push(renderReadyToRunData(readyToRun));
  }
  out.push(`${renderWarningList(readyToRun.issues)}</details>`);
};

export const renderCompositeReadyToRun = (
  image: Pick<PeClrHeader, "readyToRun">, out: string[]
): void => {
  out.push(renderPeSectionStart("ReadyToRun composite header"));
  renderReadyToRun(image, out);
  out.push(renderPeSectionEnd());
};
