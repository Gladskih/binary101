"use strict";

import type { AuthenticodeCheckStatus } from "./index.js";
import type { Certificate } from "./pkijs-runtime.js";
import { describeError, normalizeLegacyCertificateSignatureAlgorithm } from "./pkijs-support.js";
import {
  shouldVerifyRsaPkcs1v15Locally,
  verifyRsaPkcs1v15Signature
} from "./rsa-pkcs1v15.js";

export type CertificateSignatureStatus = {
  status: AuthenticodeCheckStatus;
  detail?: string;
};

type IssuerCandidateEvaluation = {
  index: number;
  signatureStatus: CertificateSignatureStatus;
  continuationScore: number;
};

export const verifyCertificateSignature = async (
  certificate: Certificate,
  issuerCertificate?: Certificate
): Promise<CertificateSignatureStatus> => {
  try {
    normalizeLegacyCertificateSignatureAlgorithm(certificate);
    if (issuerCertificate) normalizeLegacyCertificateSignatureAlgorithm(issuerCertificate);
    if (shouldVerifyRsaPkcs1v15Locally(certificate.signatureAlgorithm)) {
      const localResult = await verifyRsaPkcs1v15Signature(
        certificate.tbsView,
        certificate.signatureValue.valueBlock.valueHexView,
        (issuerCertificate ?? certificate).subjectPublicKeyInfo,
        certificate.signatureAlgorithm
      );
      if (localResult) {
        const status = localResult.verified == null ? "unknown" : localResult.verified ? "pass" : "fail";
        return { status, ...(localResult.detail ? { detail: localResult.detail } : {}) };
      }
    }
    return (await certificate.verify(issuerCertificate))
      ? { status: "pass" }
      : { status: "fail", detail: "Signature verification returned false." };
  } catch (error) {
    return { status: "unknown", detail: describeError(error) };
  }
};

const isSelfSignedCertificate = (certificate: Certificate): boolean =>
  certificate.subject.isEqual(certificate.issuer);

const hasUnvisitedIssuerMatch = (
  certificates: Certificate[],
  candidateIndex: number,
  visited: ReadonlySet<number>
): boolean => {
  const candidate = certificates[candidateIndex];
  return !!candidate &&
    certificates.some(
      (certificate, index) =>
        index !== candidateIndex &&
        !visited.has(index) &&
        candidate.issuer.isEqual(certificate.subject)
    );
};

const rankSignatureStatus = (status: AuthenticodeCheckStatus): number =>
  status === "pass" ? 2 : status === "unknown" ? 1 : 0;

export const chooseBestIssuerCandidate = async (
  certificates: Certificate[],
  issuerIndexes: number[],
  currentCertificate: Certificate,
  visited: ReadonlySet<number>
): Promise<IssuerCandidateEvaluation | undefined> => {
  let bestCandidate: IssuerCandidateEvaluation | undefined;
  for (const candidateIndex of issuerIndexes) {
    const candidateCertificate = certificates[candidateIndex];
    if (!candidateCertificate) continue;
    const signatureStatus = await verifyCertificateSignature(currentCertificate, candidateCertificate);
    const continuationScore = isSelfSignedCertificate(candidateCertificate)
      ? 2
      : hasUnvisitedIssuerMatch(certificates, candidateIndex, visited)
        ? 1
        : 0;
    const candidate: IssuerCandidateEvaluation = {
      index: candidateIndex,
      signatureStatus,
      continuationScore
    };
    if (!bestCandidate) {
      bestCandidate = candidate;
      continue;
    }
    const candidateRank = rankSignatureStatus(candidate.signatureStatus.status);
    const bestRank = rankSignatureStatus(bestCandidate.signatureStatus.status);
    if (candidateRank > bestRank) {
      bestCandidate = candidate;
      continue;
    }
    if (candidateRank === bestRank && candidate.continuationScore > bestCandidate.continuationScore) {
      bestCandidate = candidate;
    }
  }
  return bestCandidate;
};
