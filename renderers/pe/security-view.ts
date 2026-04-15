"use strict";
import { humanSize, hex } from "../../binary-utils.js";
import { dd, rowOpts, safe } from "../../html-utils.js";
import type { ParsedWinCertificate } from "../../analyzers/pe/authenticode/index.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { renderAuthenticodeTree } from "./security-tree.js";

type PeSecuritySection = NonNullable<PeWindowsParseResult["security"]>;

const WIN_CERTIFICATE_TYPES: Array<[number, string, string]> = [
  [0x0001, "X.509", "Individual X.509 certificate blob."],
  [0x0002, "PKCS#7", "Authenticode SignedData / CMS signature."],
  [0x0009, "TS stack", "Terminal Services stack signing certificate."],
  [0x000a, "Catalog", "PKCS#7 catalog signature, often for drivers."],
  [0x0ef0, "EFI PKCS1.5", "UEFI PKCS#1 v1.5 certificate format."],
  [0x0ef1, "EFI GUID", "UEFI GUID-defined certificate format."],
  [0x0ef2, "EFI signed", "UEFI signed-data certificate format."]
];

const renderWarningSection = (title: string, warnings: string[] | undefined): string =>
  warnings?.length
    ? `<div class="peSecuritySection"><div class="smallNote" style="color:var(--warn-fg)"><b>${title}</b></div><ul class="peSecurityList peSecurityList--warn">${warnings.map(warning => `<li>${safe(warning)}</li>`).join("")}</ul></div>`
    : "";

const renderCertificateType = (certificateType: number, typeName: string): string =>
  WIN_CERTIFICATE_TYPES.some(([type]) => type === certificateType)
    ? rowOpts(certificateType, WIN_CERTIFICATE_TYPES)
    : `<span class="mono">${hex(certificateType, 4)}</span> (${safe(typeName)})`;

const renderCertificateCard = (certificate: ParsedWinCertificate, index: number): string => {
  const lengthLabel =
    `${humanSize(certificate.length)}` +
    `${certificate.availableBytes < certificate.length ? " (truncated)" : ""}`;
  return (
    `<section class="peSecurityCertCard">` +
    `<div class="peSecurityCertHeader"><span class="peSecurityCertTitle">Certificate #${index + 1}</span></div>` +
    `<dl>` +
    dd("Offset", hex(certificate.offset, 8)) +
    dd("Length", safe(lengthLabel)) +
    dd("Revision", `${hex(certificate.revision, 4)} (${safe(certificate.revisionName)})`) +
    dd("Type", renderCertificateType(certificate.certificateType, certificate.typeName)) +
    `</dl>` +
    `${certificate.authenticode ? renderAuthenticodeTree(certificate) : ""}` +
    `${!certificate.authenticode ? renderWarningSection("Structural warnings", certificate.warnings) : ""}` +
    `</section>`
  );
};

export function renderSecurity(security: PeSecuritySection, out: string[]): void {
  out.push(
    renderPeSectionStart(
      "Security (WIN_CERTIFICATE)",
      `${security.count ?? 0} record${(security.count ?? 0) === 1 ? "" : "s"}`
    )
  );
  out.push(`<dl>`);
  out.push(
    dd(
      "Certificate records",
      String(security.count ?? 0),
      "Number of certificate blobs present (Authenticode)."
    )
  );
  out.push(`</dl>`);
  if (security.warnings?.length) {
    out.push(`<ul class="smallNote">`);
    security.warnings.forEach(warning => out.push(`<li>${safe(warning)}</li>`));
    out.push(`</ul>`);
  }
  if (security.certs?.length) {
    out.push(`<div class="peSecurityCertList">`);
    security.certs.forEach((certificate, index) => out.push(renderCertificateCard(certificate, index)));
    out.push(`</div>`);
  }
  out.push(renderPeSectionEnd());
}
