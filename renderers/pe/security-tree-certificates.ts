"use strict";

import type { AuthenticodeInfo } from "../../analyzers/pe/authenticode/index.js";
import {
  createCheckBadge,
  findIssuerCandidateIndexes,
  getCertificate,
  getReferenceValidityCheck
} from "./security-tree-checks.js";
import {
  formatCertificateTitle,
  formatDistinguishedNameTooltip
} from "./security-tree-dn.js";
import {
  createInfoBadge,
  createRoleBadge,
  createStatusBadge,
  filterBadges,
  formatCheckDetail,
  renderTreeMeta,
  renderTreeNode
} from "./security-tree-markup.js";

const resolveCertificateRole = (
  auth: AuthenticodeInfo,
  pathIndexes: number[],
  depth: number,
  leafRole: string
): string => {
  if (depth === 0) return leafRole;
  const certificate = getCertificate(auth.certificates, pathIndexes[depth]);
  const isRoot = !!certificate?.subject && certificate.subject === certificate.issuer;
  const isLeafRoot = depth === pathIndexes.length - 1;
  if (isRoot) return "Root";
  if (isLeafRoot) return "Top issuer";
  return "Issuer";
};

const renderAlternativeIssuerBranch = (
  auth: AuthenticodeInfo,
  certificateIndex: number,
  visitedIndexes: ReadonlySet<number>
): string => {
  const certificate = getCertificate(auth.certificates, certificateIndex);
  const nextVisited = new Set(visitedIndexes);
  nextVisited.add(certificateIndex);
  const childIndexes = findIssuerCandidateIndexes(auth, certificateIndex, nextVisited);
  return renderTreeNode(
    formatCertificateTitle(certificateIndex, certificate?.subject),
    [
      createRoleBadge(
        certificate?.subject === certificate?.issuer ? "Cross-signed root" : "Alt issuer",
        "certificate",
        "Alternative issuer candidate present in the embedded CMS."
      ),
      createInfoBadge("DN", "Issuer DN of the parent certificate matches this certificate subject DN."),
      createInfoBadge(`Cert ${certificateIndex + 1}`, `Embedded certificate ${certificateIndex + 1}`)
    ],
    [
      renderTreeMeta("Issuer", certificate?.issuer),
      renderTreeMeta("Serial", certificate?.serialNumber),
      renderTreeMeta(
        "Validity",
        certificate?.notBefore || certificate?.notAfter
          ? `${certificate?.notBefore || "?"} -> ${certificate?.notAfter || "?"}`
          : undefined
      )
    ],
    childIndexes.map(index => renderAlternativeIssuerBranch(auth, index, nextVisited)).join(""),
    formatDistinguishedNameTooltip(certificate?.subject)
  );
};

const renderReferenceValidityBadge = (
  auth: AuthenticodeInfo,
  label: string,
  certificateIndex: number
) => {
  const referenceValidity = getReferenceValidityCheck(auth, label, certificateIndex);
  if (!referenceValidity) return undefined;
  const referenceLabel = referenceValidity.id.includes("signing time")
    ? "At sign"
    : referenceValidity.id.includes("countersignature time")
      ? "At ts"
      : "At ref";
  return createStatusBadge(
    referenceLabel,
    referenceValidity.status,
    formatCheckDetail(referenceValidity.title, referenceValidity.detail)
  );
};

const renderCertificatePath = (
  auth: AuthenticodeInfo,
  label: string | undefined,
  pathIndexes: number[],
  depth: number,
  leafRole: string,
  visitedIndexes: ReadonlySet<number>
): string => {
  const certificateIndex = pathIndexes[depth];
  if (certificateIndex == null) return "";
  const certificate = getCertificate(auth.certificates, certificateIndex);
  const nextCertificateIndex = pathIndexes[depth + 1];
  const currentVisited = new Set(visitedIndexes);
  currentVisited.add(certificateIndex);
  const alternativeIssuerIndexes = findIssuerCandidateIndexes(auth, certificateIndex, currentVisited).filter(
    index => index !== nextCertificateIndex
  );
  return renderTreeNode(
    formatCertificateTitle(certificateIndex, certificate?.subject),
    filterBadges([
      createRoleBadge(resolveCertificateRole(auth, pathIndexes, depth, leafRole), "certificate"),
      createInfoBadge(`Cert ${certificateIndex + 1}`, `Embedded certificate ${certificateIndex + 1}`),
      depth === 0 && label ? createCheckBadge(auth, `${label}-key-usage`, "KU") : undefined,
      depth === 0 && label ? createCheckBadge(auth, `${label}-eku`, "EKU") : undefined,
      label
        ? createCheckBadge(
            auth,
            `${label}-certificate-${certificateIndex + 1}-current-validity`,
            "Now"
          )
        : undefined,
      label ? renderReferenceValidityBadge(auth, label, certificateIndex) : undefined,
      label
        ? createCheckBadge(auth, `${label}-certificate-${certificateIndex + 1}-issuer-match`, "Issuer")
        : undefined,
      label
        ? createCheckBadge(auth, `${label}-certificate-${certificateIndex + 1}-issuer-signature`, "Chain")
        : undefined,
      label
        ? createCheckBadge(auth, `${label}-certificate-${certificateIndex + 1}-self-signed`, "Self")
        : undefined,
      label && nextCertificateIndex != null
        ? createCheckBadge(
            auth,
            `${label}-issuer-${certificateIndex + 1}-${nextCertificateIndex + 1}-ca`,
            "CA"
          )
        : undefined,
      label && nextCertificateIndex != null
        ? createCheckBadge(
            auth,
            `${label}-issuer-${certificateIndex + 1}-${nextCertificateIndex + 1}-keyusage`,
            "CertSign"
          )
        : undefined
    ]),
    [
      renderTreeMeta("Issuer", certificate?.issuer),
      renderTreeMeta("Serial", certificate?.serialNumber),
      renderTreeMeta(
        "Validity",
        certificate?.notBefore || certificate?.notAfter
          ? `${certificate?.notBefore || "?"} -> ${certificate?.notAfter || "?"}`
          : undefined
      )
    ],
    [
      depth + 1 < pathIndexes.length
        ? renderCertificatePath(auth, label, pathIndexes, depth + 1, leafRole, currentVisited)
        : "",
      ...alternativeIssuerIndexes.map(index => renderAlternativeIssuerBranch(auth, index, currentVisited))
    ]
      .filter(Boolean)
      .join(""),
    formatDistinguishedNameTooltip(certificate?.subject)
  );
};

export const renderCertificateBranch = (
  auth: AuthenticodeInfo,
  label: string | undefined,
  pathIndexes: number[] | undefined,
  certificateIndex: number | undefined,
  leafRole: string,
  missingTitle: string
): string => {
  const resolvedIndexes =
    pathIndexes?.length
      ? pathIndexes
      : certificateIndex != null && certificateIndex >= 0
        ? [certificateIndex]
        : [];
  return resolvedIndexes.length
    ? renderCertificatePath(auth, label, resolvedIndexes, 0, leafRole, new Set<number>())
    : renderTreeNode(
        missingTitle,
        [createStatusBadge("Missing", "unknown", missingTitle)],
        []
      );
};
