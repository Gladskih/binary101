"use strict";

import type {
  AuthenticodeCertificateTrustInfo,
  AuthenticodeInfo,
  X509CertificateInfo
} from "../../analyzers/pe/authenticode/index.js";
import {
  createInfoBadge,
  createStatusBadge,
  formatCheckDetail,
  type TreeBadge
} from "./security-tree-markup.js";

export const getCertificate = (
  certificates: X509CertificateInfo[] | undefined,
  certificateIndex: number | undefined
): X509CertificateInfo | undefined =>
  certificateIndex != null && certificateIndex >= 0 ? certificates?.[certificateIndex] : undefined;

const getCheckById = (auth: AuthenticodeInfo, id: string) =>
  auth.verification?.checks?.find(check => check.id === id);

export const getCertificateTrust = (
  auth: AuthenticodeInfo,
  certificateIndex: number | undefined
): AuthenticodeCertificateTrustInfo | undefined =>
  certificateIndex != null && certificateIndex >= 0
    ? auth.verification?.trustPolicy?.certificates.find(
        certificate => certificate.certificateIndex === certificateIndex
      )
    : undefined;

const formatTrustStores = (trust: AuthenticodeCertificateTrustInfo): string =>
  trust.stores?.length ? ` Stores: ${trust.stores.join(", ")}.` : "";

const formatTrustThumbprint = (trust: AuthenticodeCertificateTrustInfo): string =>
  trust.sha1Thumbprint ? ` SHA-1 ${trust.sha1Thumbprint}.` : "";

const formatTrustAnchor = (trust: AuthenticodeCertificateTrustInfo): string => {
  if (!trust.anchorSha1Thumbprint) return "";
  const subject = trust.anchorSubject ? ` ${trust.anchorSubject}.` : "";
  return ` Anchor SHA-1 ${trust.anchorSha1Thumbprint}.${subject}`;
};

const formatTrustDetail = (
  auth: AuthenticodeInfo,
  trust: AuthenticodeCertificateTrustInfo
): string => {
  const checkedAt = auth.verification?.trustPolicy?.generatedAt || "unknown date";
  if (trust.status === "revoked") {
    return `Certificate chains to the Windows Disallowed CA snapshot as of ${checkedAt}.` +
      `${formatTrustThumbprint(trust)}${formatTrustAnchor(trust)}${formatTrustStores(trust)}`;
  }
  if (trust.status === "trusted") {
    return `Certificate chains to the Windows trusted CA snapshot as of ${checkedAt}.` +
      `${formatTrustThumbprint(trust)}${formatTrustAnchor(trust)}${formatTrustStores(trust)}`;
  }
  return `Certificate is not in the Windows trusted or disallowed CA snapshot as of ${checkedAt}.${formatTrustThumbprint(trust)}`;
};

export const createCheckBadge = (
  auth: AuthenticodeInfo,
  id: string,
  label: string
): TreeBadge | undefined => {
  const check = getCheckById(auth, id);
  return check
    ? createStatusBadge(label, check.status, formatCheckDetail(check.title, check.detail))
    : undefined;
};

export const createCertificateTrustBadge = (
  auth: AuthenticodeInfo,
  certificateIndex: number | undefined
): TreeBadge | undefined => {
  const trust = getCertificateTrust(auth, certificateIndex);
  if (!trust) return undefined;
  if (trust.status === "trusted") return createStatusBadge("Trusted", "pass", formatTrustDetail(auth, trust));
  if (trust.status === "revoked") return createStatusBadge("Revoked", "fail", formatTrustDetail(auth, trust));
  return createStatusBadge("Not in store", "unknown", formatTrustDetail(auth, trust));
};

export const createCertificatePathTrustBadge = (
  auth: AuthenticodeInfo,
  pathIndexes: number[] | undefined
): TreeBadge | undefined => {
  if (!auth.verification?.trustPolicy || !pathIndexes?.length) return undefined;
  const revoked = pathIndexes.map(index => getCertificateTrust(auth, index)).find(
    trust => trust?.status === "revoked"
  );
  if (revoked) return createStatusBadge("Revoked", "fail", formatTrustDetail(auth, revoked));
  const topCertificateTrust = getCertificateTrust(auth, pathIndexes[pathIndexes.length - 1]);
  if (topCertificateTrust?.status === "trusted") {
    return createStatusBadge("Trusted", "pass", formatTrustDetail(auth, topCertificateTrust));
  }
  if (topCertificateTrust) {
    return createStatusBadge("Not trusted", "unknown", formatTrustDetail(auth, topCertificateTrust));
  }
  return createStatusBadge(
    "Not trusted",
    "unknown",
    `Certificate path was not found in the Windows CA snapshot as of ${auth.verification.trustPolicy.generatedAt}.`
  );
};

export const createTrustSnapshotBadge = (auth: AuthenticodeInfo): TreeBadge | undefined =>
  auth.verification?.trustPolicy
    ? createInfoBadge(
        "Trust snapshot",
        `Windows CA snapshot generated at ${auth.verification.trustPolicy.generatedAt}.`
      )
    : undefined;

export const getReferenceValidityCheck = (
  auth: AuthenticodeInfo,
  label: string,
  certificateIndex: number
) =>
  auth.verification?.checks?.find(
    check =>
      check.id.startsWith(`${label}-certificate-${certificateIndex + 1}-`) &&
      check.id.endsWith("-validity") &&
      check.id !== `${label}-certificate-${certificateIndex + 1}-current-validity`
  );

export const collectUsedCertificateIndexes = (auth: AuthenticodeInfo): Set<number> => {
  const used = new Set<number>();
  auth.verification?.signerVerifications?.forEach(signerVerification => {
    signerVerification.certificatePathIndexes?.forEach(index => used.add(index));
    if (signerVerification.signerCertificateIndex != null) used.add(signerVerification.signerCertificateIndex);
    signerVerification.countersignatures?.forEach(countersignature => {
      countersignature.certificatePathIndexes?.forEach(index => used.add(index));
      if (countersignature.signerCertificateIndex != null) used.add(countersignature.signerCertificateIndex);
    });
  });
  return used;
};

export const findIssuerCandidateIndexes = (
  auth: AuthenticodeInfo,
  certificateIndex: number,
  excludedIndexes: ReadonlySet<number>
): number[] => {
  const certificate = getCertificate(auth.certificates, certificateIndex);
  if (!certificate?.issuer) return [];
  return (auth.certificates ?? [])
    .map((candidate, index) => ({ candidate, index }))
    .filter(
      item =>
        item.index !== certificateIndex &&
        !excludedIndexes.has(item.index) &&
        item.candidate?.subject === certificate.issuer
    )
    .map(item => item.index);
};

export const collectConnectedCertificateIndexes = (auth: AuthenticodeInfo): Set<number> => {
  const connected = collectUsedCertificateIndexes(auth);
  const visit = (certificateIndex: number): void => {
    if (connected.has(certificateIndex)) {
      findIssuerCandidateIndexes(auth, certificateIndex, connected).forEach(index => {
        connected.add(index);
        visit(index);
      });
      return;
    }
    connected.add(certificateIndex);
    findIssuerCandidateIndexes(auth, certificateIndex, connected).forEach(index => {
      connected.add(index);
      visit(index);
    });
  };
  [...connected].forEach(visit);
  return connected;
};
