import type { PeParseResult } from "../../analyzers/pe/index.js";
import { isPeWindowsParseResult } from "../../analyzers/pe/index.js";
import { IMAGE_FILE_MACHINE_TYPES } from "../../analyzers/coff/machine.js";
import { SUBSYSTEMS } from "../../analyzers/pe/constants.js";
import { hex } from "../../binary-utils.js";
import { escapeHtmlText } from "../../html-utils.js";

const fields = (rows: readonly (readonly [string, string])[]): string =>
  `<dl class="workspaceCard__fields">${rows.map(([name, value]) =>
    `<dt>${escapeHtmlText(name)}</dt><dd>${escapeHtmlText(value)}</dd>`).join("")}</dl>`;

const enumValue = (value: number, options: readonly (readonly [number, string, string?])[]): string => {
  const name = options.find(([code]) => code === value)?.[1];
  return hex(value, 4) + (name ? ` (${name})` : "");
};

const headerPreview = (pe: PeParseResult): string => fields([
  ["COFF.Machine", enumValue(pe.coff.Machine, IMAGE_FILE_MACHINE_TYPES)],
  ...(pe.opt ? [["OptionalHeader.AddressOfEntryPoint", hex(pe.opt.AddressOfEntryPoint, 8)]] as const : []),
  ...(isPeWindowsParseResult(pe)
    ? [["OptionalHeader.Subsystem", enumValue(pe.opt.Subsystem, SUBSYSTEMS)]] as const : [])
]);

const securityPreview = (pe: PeParseResult): string => {
  if (!isPeWindowsParseResult(pe) || !pe.security) return "";
  const checks = pe.security.certs.flatMap(certificate =>
    certificate.authenticode?.verification?.checks ?? []);
  if (!checks.length) return fields([["verification.checks", pe.security.certs.some(certificate =>
    certificate.authenticode?.verification?.checks !== undefined) ? "0" : "Not reported"]]);
  return fields([["Recorded verification.checks", String(checks.length)]]) + `<p>` +
    ["pass", "fail", "unknown"].map(status =>
      `${status}: ${checks.filter(check => check.status === status).length}`).join(" · ") + `</p>`;
};

const importPreview = (pe: PeParseResult): string => {
  if (!isPeWindowsParseResult(pe)) return "";
  const modules = pe.imports.entries.map(entry => entry.dll || "(empty DLL name)");
  // Keep three names in the preview; the linked table retains every descriptor.
  return (pe.imports.warning ? `<p>${escapeHtmlText(pe.imports.warning)}</p>` : "") +
    (modules.length ? `<ul>${modules.slice(0, 3).map(name =>
      `<li>${escapeHtmlText(name)}</li>`).join("")}</ul>` : "") +
    (modules.length > 3 ? `<p class="smallNote">${modules.length - 3} more</p>` : "");
};

const resourcePreview = (pe: PeParseResult): string => {
  if (!isPeWindowsParseResult(pe) || !pe.resources?.issues?.length) return "";
  return `<ul>${pe.resources.issues.map(issue => `<li>${escapeHtmlText(issue)}</li>`).join("")}</ul>`;
};

export const renderPeSectionPreview = (pe: PeParseResult, key: string): string => {
  if (key === "dos-header") return fields([
    ["e_magic", pe.dos.e_magic], ["e_lfanew", hex(pe.dos.e_lfanew, 8)]
  ]);
  if (key === "pe-headers") return headerPreview(pe);
  if (key === "security") return securityPreview(pe);
  if (key === "resources") return resourcePreview(pe);
  return key === "imports" ? importPreview(pe) : "";
};
