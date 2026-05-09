"use strict";

import type {
  AuthenticodeCheckStatus,
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

const hasSnapshotAnchor = (trust: AuthenticodeCertificateTrustInfo): boolean =>
  !!trust.anchorSha1Thumbprint;

const formatTrustDetail = (
  auth: AuthenticodeInfo,
  trust: AuthenticodeCertificateTrustInfo
): string => {
  const checkedAt = auth.verification?.trustPolicy?.generatedAt || "unknown date";
  if (trust.status === "revoked") {
    return `Certificate ${hasSnapshotAnchor(trust) ? "chains to" : "is in"} the Windows ` +
      `Disallowed CA snapshot as of ${checkedAt}.` +
      `${formatTrustThumbprint(trust)}${formatTrustAnchor(trust)}${formatTrustStores(trust)}`;
  }
  if (trust.status === "trusted") {
    return `Certificate ${hasSnapshotAnchor(trust) ? "chains to" : "is in"} the Windows ` +
      `trusted CA snapshot as of ${checkedAt}.` +
      `${formatTrustThumbprint(trust)}${formatTrustAnchor(trust)}${formatTrustStores(trust)}`;
  }
  return `Certificate path does not reach the Windows trusted or disallowed CA snapshot ` +
    `as of ${checkedAt}.${formatTrustThumbprint(trust)}`;
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

export const createNeutralUnknownCheckBadge = (
  auth: AuthenticodeInfo,
  id: string,
  label: string
): TreeBadge | undefined => {
  const check = getCheckById(auth, id);
  if (!check) return undefined;
  const detail = formatCheckDetail(check.title, check.detail);
  return check.status === "unknown"
    ? createInfoBadge(label, detail)
    : createStatusBadge(label, check.status, detail);
};

export const createCertificateTrustBadge = (
  auth: AuthenticodeInfo,
  certificateIndex: number | undefined
): TreeBadge | undefined => {
  const trust = getCertificateTrust(auth, certificateIndex);
  if (!trust) return undefined;
  if (trust.status === "trusted") {
    return createStatusBadge(
      hasSnapshotAnchor(trust) ? "Chain trusted" : "In store",
      "pass",
      formatTrustDetail(auth, trust)
    );
  }
  if (trust.status === "revoked") {
    return createStatusBadge(
      hasSnapshotAnchor(trust) ? "Disallowed chain" : "Disallowed",
      "fail",
      formatTrustDetail(auth, trust)
    );
  }
  return createStatusBadge("Not trusted", "unknown", formatTrustDetail(auth, trust));
};

export const createCertificateStoreFactBadge = (
  auth: AuthenticodeInfo,
  certificateIndex: number | undefined
): TreeBadge | undefined => {
  const trust = getCertificateTrust(auth, certificateIndex);
  if (!trust || trust.status === "unknown" || hasSnapshotAnchor(trust)) return undefined;
  return trust.status === "trusted"
    ? createStatusBadge("In store", "pass", formatTrustDetail(auth, trust))
    : createStatusBadge("Disallowed", "fail", formatTrustDetail(auth, trust));
};

export const createCertificateKnownTrustBadge = (
  auth: AuthenticodeInfo,
  certificateIndex: number | undefined
): TreeBadge | undefined => {
  const trust = getCertificateTrust(auth, certificateIndex);
  if (!trust || trust.status === "unknown") return undefined;
  return trust.status === "trusted"
    ? createStatusBadge(
        hasSnapshotAnchor(trust) ? "Chain trusted" : "In store",
        "pass",
        formatTrustDetail(auth, trust)
      )
    : createStatusBadge(
        hasSnapshotAnchor(trust) ? "Disallowed chain" : "Disallowed",
        "fail",
        formatTrustDetail(auth, trust)
      );
};

const findCertificatePathTrust = (
  auth: AuthenticodeInfo,
  pathIndexes: number[],
  status: AuthenticodeCertificateTrustInfo["status"]
): AuthenticodeCertificateTrustInfo | undefined =>
  pathIndexes.map(index => getCertificateTrust(auth, index)).find(trust => trust?.status === status);

export const getCertificatePathStatus = (
  auth: AuthenticodeInfo,
  pathIndexes: number[] | undefined
): AuthenticodeCheckStatus | undefined => {
  if (!auth.verification?.trustPolicy || !pathIndexes?.length) return undefined;
  if (findCertificatePathTrust(auth, pathIndexes, "revoked")) return "fail";
  return findCertificatePathTrust(auth, pathIndexes, "trusted") ? "pass" : "unknown";
};

export const createCertificatePathTrustBadge = (
  auth: AuthenticodeInfo,
  pathIndexes: number[] | undefined
): TreeBadge | undefined => {
  if (!auth.verification?.trustPolicy || !pathIndexes?.length) return undefined;
  const revoked = findCertificatePathTrust(auth, pathIndexes, "revoked");
  if (revoked) return createStatusBadge("Disallowed chain", "fail", formatTrustDetail(auth, revoked));
  const trusted = findCertificatePathTrust(auth, pathIndexes, "trusted");
  if (trusted) {
    return createStatusBadge("Chain trusted", "pass", formatTrustDetail(auth, trusted));
  }
  const topCertificateTrust = getCertificateTrust(auth, pathIndexes[pathIndexes.length - 1]);
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
