"use strict";
import { humanSize, hex } from "../../binary-utils.js";
import { dd, rowOpts, safe } from "../../html-utils.js";
import type {
  AuthenticodeInfo,
  AuthenticodeSignerInfo,
  AuthenticodeSignerVerificationInfo,
  ParsedWinCertificate,
  X509CertificateInfo
} from "../../analyzers/pe/authenticode/index.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import {
  AUTHENTICODE_PAYLOAD_TYPES,
  CMS_CONTENT_TYPES,
  DIGEST_ALGORITHM_TYPES,
  renderNamedOptionChips
} from "./security-chips.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

type PeSecuritySection = NonNullable<PeWindowsParseResult["security"]>;
type ValidationTone = "ok" | "warn" | "dim";

const WIN_CERTIFICATE_TYPES: Array<[number, string, string]> = [
  [0x0001, "X.509", "Individual X.509 certificate blob."],
  [0x0002, "PKCS#7", "Authenticode SignedData / CMS signature."],
  [0x0009, "TS stack", "Terminal Services stack signing certificate."],
  [0x000a, "Catalog", "PKCS#7 catalog signature, often for drivers."],
  [0x0ef0, "EFI PKCS1.5", "UEFI PKCS#1 v1.5 certificate format."],
  [0x0ef1, "EFI GUID", "UEFI GUID-defined certificate format."],
  [0x0ef2, "EFI signed", "UEFI signed-data certificate format."]
];

const joinSentence = (parts: string[]): string => `${parts.filter(Boolean).join("; ")}.`;

const formatDigestValue = (
  label: string,
  value: string | undefined,
  algorithm: string | undefined
): string =>
  value
    ? dd(
        algorithm ? `${label} (${safe(algorithm)})` : label,
        `<span class="mono">${safe(value)}</span>`
      )
    : "";

const formatSignerSummary = (signer: AuthenticodeSignerInfo, index: number): string | null => {
  const parts: string[] = [];
  if (signer.issuer) parts.push(`Issuer ${signer.issuer}`);
  if (signer.serialNumber) parts.push(`Serial ${signer.serialNumber}`);
  if (signer.digestAlgorithmName || signer.digestAlgorithm) {
    parts.push(`Digest ${signer.digestAlgorithmName || signer.digestAlgorithm}`);
  }
  if (signer.signatureAlgorithmName || signer.signatureAlgorithm) {
    parts.push(`Signature ${signer.signatureAlgorithmName || signer.signatureAlgorithm}`);
  }
  if (signer.signingTime) parts.push(`Time ${signer.signingTime}`);
  return parts.length
    ? `<li><b>Signer ${index + 1}</b>: ${safe(parts.join(", "))}</li>`
    : null;
};

const formatCertificateSummary = (
  certificate: X509CertificateInfo,
  index: number
): string | null => {
  const parts: string[] = [];
  if (certificate.subject) parts.push(`Subject ${certificate.subject}`);
  if (certificate.issuer) parts.push(`Issuer ${certificate.issuer}`);
  if (certificate.serialNumber) parts.push(`Serial ${certificate.serialNumber}`);
  if (certificate.notBefore || certificate.notAfter) {
    parts.push(`Validity ${certificate.notBefore || "?"} -> ${certificate.notAfter || "?"}`);
  }
  return parts.length
    ? `<li><b>Certificate ${index + 1}</b>: ${safe(parts.join(", "))}</li>`
    : null;
};

const formatSignerVerification = (
  verification: AuthenticodeSignerVerificationInfo
): string => {
  const prefix = `Signer ${verification.index + 1}: `;
  if (verification.signatureVerified === true) return prefix + "signature verified.";
  if (verification.signatureVerified === false) {
    return verification.message
      ? `${prefix}signature check failed. ${verification.message}`
      : prefix + "signature check failed.";
  }
  return verification.message
    ? `${prefix}verification was inconclusive. ${verification.message}`
    : prefix + "verification was inconclusive.";
};

const renderListSection = (title: string, items: string[]): string =>
  items.length
    ? `<div class="peSecuritySection"><div class="smallNote"><b>${title}</b></div><ul class="peSecurityList">${items.join("")}</ul></div>`
    : "";

const renderWarningSection = (title: string, warnings: string[] | undefined): string =>
  warnings?.length
    ? `<div class="peSecuritySection"><div class="smallNote" style="color:var(--warn-fg)"><b>${title}</b></div><ul class="peSecurityList peSecurityList--warn">${warnings.map(warning => `<li>${safe(warning)}</li>`).join("")}</ul></div>`
    : "";

const describeValidationTone = (
  auth: AuthenticodeInfo
): { tone: ValidationTone; title: string; summary: string; icon: string } => {
  const verification = auth.verification;
  if (!verification) {
    return {
      tone: "dim",
      title: "Signature integrity check unavailable",
      summary: "No cryptographic verification result is attached to this CMS payload.",
      icon: "&#9432;"
    };
  }
  const signerVerifications = verification.signerVerifications ?? [];
  const anySignerInvalid = signerVerifications.some(
    signerVerification => signerVerification.signatureVerified === false
  );
  const allSignersValid =
    signerVerifications.length > 0 &&
    signerVerifications.every(
      signerVerification => signerVerification.signatureVerified === true
    );
  if (verification.fileDigestMatches === true && allSignersValid) {
    return {
      tone: "ok",
      title: "Signature integrity check passed",
      summary: joinSentence([
        "Embedded file digest matches this file",
        "all CMS signer signatures verified"
      ]),
      icon: "&#10003;"
    };
  }
  if (verification.fileDigestMatches === false || anySignerInvalid) {
    return {
      tone: "warn",
      title: "Signature integrity check failed",
      summary: joinSentence([
        verification.fileDigestMatches === false
          ? "embedded file digest does not match this file"
          : "",
        anySignerInvalid ? "at least one CMS signer verification failed" : ""
      ]),
      icon: "&#10007;"
    };
  }
  return {
    tone: "dim",
    title: "Signature integrity check incomplete",
    summary: joinSentence([
      verification.fileDigestMatches === true
        ? "Embedded file digest matches this file"
        : "file digest match was not established",
      signerVerifications.length
        ? "some signer checks did not reach a clear pass/fail verdict"
        : "no signer verification result is available"
    ]),
    icon: "&#9888;"
  };
};

const renderValidationSummary = (auth: AuthenticodeInfo): string => {
  const verdict = describeValidationTone(auth);
  return (
    `<div class="peSecurityValidation peSecurityValidation--${verdict.tone}">` +
    `<div class="peSecurityValidationTitle">` +
    `<span class="peSecurityValidationIcon">${verdict.icon}</span>` +
    `<span>${safe(verdict.title)}</span>` +
    `</div>` +
    `<div class="smallNote peSecurityValidationSummary">${safe(verdict.summary)}</div>` +
    `<div class="smallNote peSecurityValidationSummary">` +
    `This checks signature integrity only. ` +
    `Certificate-chain trust, revocation, EKU, and local platform trust ` +
    `were not evaluated.` +
    `</div></div>`
  );
};

const renderAuthenticodeFacts = (auth: AuthenticodeInfo): string => {
  const rows = [
    auth.contentTypeName
      ? dd(
          "CMS content",
          renderNamedOptionChips([auth.contentTypeName], CMS_CONTENT_TYPES)
        )
      : "",
    auth.payloadContentTypeName
      ? dd(
          "Signed payload",
          renderNamedOptionChips([auth.payloadContentTypeName], AUTHENTICODE_PAYLOAD_TYPES)
        )
      : "",
    auth.digestAlgorithms?.length
      ? dd(
          "Digest algorithms",
          renderNamedOptionChips(auth.digestAlgorithms, DIGEST_ALGORITHM_TYPES)
        )
      : "",
    formatDigestValue(
      "Embedded file digest",
      auth.fileDigest,
      auth.fileDigestAlgorithmName || auth.fileDigestAlgorithm
    ),
    formatDigestValue(
      "Computed file digest",
      auth.verification?.computedFileDigest,
      auth.fileDigestAlgorithmName || auth.fileDigestAlgorithm
    ),
    auth.verification?.fileDigestMatches != null
      ? dd(
          "Digest match",
          auth.verification.fileDigestMatches
            ? `<span style="color:var(--ok-fg);font-weight:600">Yes</span>`
            : `<span style="color:var(--warn-fg);font-weight:600">No</span>`
        )
      : "",
    auth.signerCount != null ? dd("Signers", String(auth.signerCount)) : "",
    auth.certificateCount != null ? dd("Certificates", String(auth.certificateCount)) : ""
  ].filter(Boolean);
  return rows.length ? `<dl>${rows.join("")}</dl>` : "";
};

const renderCertificateType = (certificateType: number, typeName: string): string =>
  WIN_CERTIFICATE_TYPES.some(([type]) => type === certificateType)
    ? rowOpts(certificateType, WIN_CERTIFICATE_TYPES)
    : `<span class="mono">${hex(certificateType, 4)}</span> (${safe(typeName)})`;

const renderCertificateCard = (certificate: ParsedWinCertificate, index: number): string => {
  const lengthLabel =
    `${humanSize(certificate.length)}` +
    `${certificate.availableBytes < certificate.length ? " (truncated)" : ""}`;
  const structuralWarnings = certificate.warnings ?? [];
  const verificationWarnings = certificate.authenticode?.verification?.warnings ?? [];
  const signerItems =
    certificate.authenticode?.signers
      ?.map(formatSignerSummary)
      .filter((item): item is string => item != null) ?? [];
  const signerVerificationItems =
    certificate.authenticode?.verification?.signerVerifications
      ?.map(formatSignerVerification)
      .map(item => `<li>${safe(item)}</li>`) ?? [];
  const certificateItems =
    certificate.authenticode?.certificates
      ?.map(formatCertificateSummary)
      .filter((item): item is string => item != null) ?? [];
  return (
    `<section class="peSecurityCertCard">` +
    `<div class="peSecurityCertHeader"><span class="peSecurityCertTitle">Certificate #${index + 1}</span></div>` +
    `<dl>` +
    dd("Offset", hex(certificate.offset, 8)) +
    dd("Length", safe(lengthLabel)) +
    dd("Revision", `${hex(certificate.revision, 4)} (${safe(certificate.revisionName)})`) +
    dd("Type", renderCertificateType(certificate.certificateType, certificate.typeName)) +
    `</dl>` +
    `${certificate.authenticode ? renderValidationSummary(certificate.authenticode) : ""}` +
    `${certificate.authenticode ? renderAuthenticodeFacts(certificate.authenticode) : ""}` +
    `${renderListSection("Signer verification", signerVerificationItems)}` +
    `${renderListSection("Signer details", signerItems)}` +
    `${renderListSection("Certificate details", certificateItems)}` +
    `${renderWarningSection("Verification warnings", verificationWarnings)}` +
    `${renderWarningSection("Structural warnings", structuralWarnings)}` +
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
