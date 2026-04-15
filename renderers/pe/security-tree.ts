"use strict";

import type {
  AuthenticodeCounterSignatureInfo,
  AuthenticodeInfo,
  AuthenticodeSignerInfo,
  AuthenticodeSignerVerificationInfo,
  ParsedWinCertificate,
} from "../../analyzers/pe/authenticode/index.js";
import {
  createCheckBadge,
  getCertificate,
} from "./security-tree-checks.js";
import { renderCertificateBranch } from "./security-tree-certificates.js";
import {
  renderAdditionalCertificatesNode,
  renderTrustGapsNode,
  renderWarningsNode
} from "./security-tree-extra-branches.js";
import {
  formatDistinguishedNameTooltip,
  formatSignerTitle
} from "./security-tree-dn.js";
import {
  createInfoBadge,
  createRoleBadge,
  createStatusBadge,
  filterBadges,
  renderTreeMeta,
  renderTreeNode
} from "./security-tree-markup.js";

const renderCountersignatureNode = (
  auth: AuthenticodeInfo,
  signerLabel: string,
  countersignature: AuthenticodeCounterSignatureInfo
): string => {
  const counterLabel = `${signerLabel} countersignature ${countersignature.index + 1}`;
  const countersignerSubject = getCertificate(
    auth.certificates,
    countersignature.signerCertificateIndex
  )?.subject;
  return renderTreeNode(
    `Countersignature ${countersignature.index + 1}: ${countersignerSubject || "Subject absent"}`,
    filterBadges([
      createRoleBadge("Timestamp", "countersignature"),
      createCheckBadge(auth, `${counterLabel}-signature`, "Sig"),
      createCheckBadge(auth, `${counterLabel}-message-digest`, "Digest"),
      createCheckBadge(auth, `${counterLabel}-certificate`, "Cert"),
      createCheckBadge(
        auth,
        `${signerLabel}-countersignature-${countersignature.index + 1}-chronology`,
        "Order"
      )
    ]),
    [
      renderTreeMeta(
        "Subject",
        getCertificate(auth.certificates, countersignature.signerCertificateIndex)?.subject
      ),
      renderTreeMeta("Time", countersignature.signingTime || "Absent"),
      renderTreeMeta("Message", countersignature.message)
    ],
    renderCertificateBranch(
      auth,
      counterLabel,
      countersignature.certificatePathIndexes,
      countersignature.signerCertificateIndex,
      "Timestamp cert",
      "No embedded countersigner certificate matched the countersignature."
    ),
    formatDistinguishedNameTooltip(countersignerSubject)
  );
};

const renderSignerNode = (
  auth: AuthenticodeInfo,
  signer: AuthenticodeSignerInfo | undefined,
  signerVerification: AuthenticodeSignerVerificationInfo | undefined,
  index: number
): string => {
  const signerLabel = `Signer ${index + 1}`;
  const signerCertificate = getCertificate(auth.certificates, signerVerification?.signerCertificateIndex);
  return renderTreeNode(
    formatSignerTitle(index, signerCertificate?.subject),
    filterBadges([
      createRoleBadge("Signer", "signer"),
      signerVerification
        ? createCheckBadge(auth, `${signerLabel}-signature`, "Sig")
        : createStatusBadge("Sig", "unknown", "No structured signer verification result is attached."),
      signerVerification ? createCheckBadge(auth, `${signerLabel}-certificate`, "Cert") : undefined,
      signerVerification?.signingTime || signer?.signingTime
        ? createInfoBadge("Time", "signingTime attribute is present.")
        : createStatusBadge("No time", "unknown", "CMS signingTime signed attribute is absent.")
    ]),
    [
      renderTreeMeta("Subject", signerCertificate?.subject),
      renderTreeMeta("Issuer", signer?.issuer),
      renderTreeMeta("Serial", signer?.serialNumber),
      renderTreeMeta("Digest", signer?.digestAlgorithmName || signer?.digestAlgorithm),
      renderTreeMeta("Signature", signer?.signatureAlgorithmName || signer?.signatureAlgorithm),
      renderTreeMeta("Claimed signing time", signerVerification?.signingTime || signer?.signingTime || "Absent")
    ],
    [
      renderCertificateBranch(
        auth,
        signerLabel,
        signerVerification?.certificatePathIndexes,
        signerVerification?.signerCertificateIndex,
        "Signer cert",
        "No embedded signer certificate matched the signer identifier."
      ),
      ...(signerVerification?.countersignatures?.map(counter =>
        renderCountersignatureNode(auth, signerLabel, counter)
      ) ?? [])
    ].join(""),
    formatDistinguishedNameTooltip(signerCertificate?.subject)
  );
};

export const renderAuthenticodeTree = (certificate: ParsedWinCertificate): string => {
  const auth = certificate.authenticode;
  if (!auth) return "";
  const signers = auth.signers ?? [];
  const signerVerifications = auth.verification?.signerVerifications ?? [];
  const signerCount = Math.max(signers.length, signerVerifications.length, auth.signerCount ?? 0);
  const children = [
    ...Array.from({ length: signerCount }, (_, index) =>
      renderSignerNode(auth, signers[index], signerVerifications[index], index)
    ),
    renderAdditionalCertificatesNode(auth),
    renderTrustGapsNode(auth.verification?.trustGaps),
    renderWarningsNode("Verification warnings", auth.verification?.warnings),
    renderWarningsNode("Structural warnings", certificate.warnings)
  ]
    .filter(Boolean)
    .join("");
  return (
    `<div class="peSecuritySection">` +
    `<div class="smallNote"><b>Certificate tree</b></div>` +
    `<div class="peSecurityTreeForest"><ul class="peSecurityTree">` +
    renderTreeNode(
      "Authenticode",
      filterBadges([
        createRoleBadge("PKCS#7", "signer"),
        createCheckBadge(auth, "file-digest-match", "Digest"),
        auth.fileDigestAlgorithmName || auth.fileDigestAlgorithm
          ? createInfoBadge(auth.fileDigestAlgorithmName ?? auth.fileDigestAlgorithm ?? "")
          : undefined,
        auth.signerCount != null ? createInfoBadge(`${auth.signerCount} signer`) : undefined,
        auth.certificateCount != null ? createInfoBadge(`${auth.certificateCount} cert`) : undefined
      ]),
      [
        renderTreeMeta("CMS content", auth.contentTypeName || auth.contentType),
        renderTreeMeta("Signed payload", auth.payloadContentTypeName || auth.payloadContentType),
        renderTreeMeta("Embedded digest", auth.fileDigest),
        renderTreeMeta("Computed digest", auth.verification?.computedFileDigest)
      ],
      children
    ) +
    `</ul></div></div>`
  );
};
