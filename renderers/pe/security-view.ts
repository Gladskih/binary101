"use strict";
import { humanSize, hex } from "../../binary-utils.js";
import { renderDefinitionRow, renderOptionChips, escapeHtml } from "../../html-utils.js";
import {
  WIN_CERTIFICATE_TYPES,
  type ParsedWinCertificate
} from "../../analyzers/pe/authenticode/index.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { renderAuthenticodeTree } from "./security-tree.js";

type PeSecuritySection = NonNullable<PeWindowsParseResult["security"]>;

const WIN_CERTIFICATE_TYPE_OPTIONS = WIN_CERTIFICATE_TYPES.map<[number, string, string]>(
  type => [type.code, type.label, type.description]
);

const renderWarningSection = (title: string, warnings: string[] | undefined): string =>
  warnings?.length
    ? `<div class="peSecuritySection"><div class="smallNote" style="color:var(--warn-fg)"><b>${title}</b></div><ul class="peSecurityList peSecurityList--warn">${warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join("")}</ul></div>`
    : "";

const renderCertificateType = (certificateType: number, typeName: string): string =>
  WIN_CERTIFICATE_TYPE_OPTIONS.some(([type]) => type === certificateType)
    ? renderOptionChips(certificateType, WIN_CERTIFICATE_TYPE_OPTIONS)
    : `<span class="mono">${hex(certificateType, 4)}</span> (${escapeHtml(typeName)})`;

const renderCertificateCard = (certificate: ParsedWinCertificate, index: number): string => {
  const lengthLabel =
    `${humanSize(certificate.length)}` +
    `${certificate.availableBytes < certificate.length ? " (truncated)" : ""}`;
  return (
    `<section class="peSecurityCertCard">` +
    `<div class="peSecurityCertHeader"><span class="peSecurityCertTitle">` +
    `WIN_CERTIFICATE record #${index + 1}</span></div>` +
    `<dl>` +
    renderDefinitionRow("Offset", hex(certificate.offset, 8)) +
    renderDefinitionRow("Length", escapeHtml(lengthLabel)) +
    renderDefinitionRow("Revision", `${hex(certificate.revision, 4)} (${escapeHtml(certificate.revisionName)})`) +
    renderDefinitionRow("Type", renderCertificateType(certificate.certificateType, certificate.typeName)) +
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
    renderDefinitionRow(
      "Certificate records",
      String(security.count ?? 0),
      "Number of parsed WIN_CERTIFICATE records; this does not establish signature validity."
    )
  );
  out.push(`</dl>`);
  if (security.warnings?.length) {
    out.push(`<ul class="smallNote">`);
    security.warnings.forEach(warning => out.push(`<li>${escapeHtml(warning)}</li>`));
    out.push(`</ul>`);
  }
  if (security.certs?.length) {
    out.push(`<div class="peSecurityCertList">`);
    security.certs.forEach((certificate, index) => out.push(renderCertificateCard(certificate, index)));
    out.push(`</div>`);
  }
  out.push(renderPeSectionEnd());
}
