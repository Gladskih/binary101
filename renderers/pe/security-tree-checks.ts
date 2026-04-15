"use strict";

import type {
  AuthenticodeInfo,
  X509CertificateInfo
} from "../../analyzers/pe/authenticode/index.js";
import {
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
