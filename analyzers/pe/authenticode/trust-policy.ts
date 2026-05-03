"use strict";

import { bufferToHex } from "../../../binary-utils.js";
import type {
  AuthenticodeCertificateTrustInfo,
  AuthenticodeTrustPolicyInfo
} from "./index.js";
import type { Certificate } from "./pkijs-runtime.js";
import { describeError, mergeWarnings } from "./pkijs-support.js";
import type {
  AuthenticodeTrustStoreCertificate,
  AuthenticodeTrustStoreSnapshot
} from "./trust-store.js";
import { normalizeThumbprint } from "./trust-store.js";

const indexCertificatesByThumbprint = (
  certificates: AuthenticodeTrustStoreCertificate[]
): Map<string, AuthenticodeTrustStoreCertificate> => {
  const index = new Map<string, AuthenticodeTrustStoreCertificate>();
  certificates.forEach(certificate => {
    const thumbprint = normalizeThumbprint(certificate.thumbprint);
    if (thumbprint) index.set(thumbprint, certificate);
  });
  return index;
};

const certificateSha1Thumbprint = async (certificate: Certificate): Promise<string> => {
  const der = certificate.toSchema().toBER(false);
  return bufferToHex(await crypto.subtle.digest("SHA-1", der)).toUpperCase();
};

const createTrustInfo = (
  certificateIndex: number,
  sha1Thumbprint: string | undefined,
  trustedCAs: ReadonlyMap<string, AuthenticodeTrustStoreCertificate>,
  revokedCAs: ReadonlyMap<string, AuthenticodeTrustStoreCertificate>
): AuthenticodeCertificateTrustInfo => {
  if (sha1Thumbprint) {
    const revoked = revokedCAs.get(sha1Thumbprint);
    if (revoked) {
      return {
        certificateIndex,
        status: "revoked",
        sha1Thumbprint,
        ...(revoked.stores?.length ? { stores: revoked.stores } : {})
      };
    }
    const trusted = trustedCAs.get(sha1Thumbprint);
    if (trusted) {
      return {
        certificateIndex,
        status: "trusted",
        sha1Thumbprint,
        ...(trusted.stores?.length ? { stores: trusted.stores } : {})
      };
    }
    return { certificateIndex, status: "unknown", sha1Thumbprint };
  }
  return { certificateIndex, status: "unknown" };
};

export const evaluateAuthenticodeTrustPolicy = async (
  certificates: Certificate[],
  trustStore: AuthenticodeTrustStoreSnapshot | undefined
): Promise<AuthenticodeTrustPolicyInfo | undefined> => {
  if (!trustStore?.generatedAt) return undefined;
  const trustedCAs = indexCertificatesByThumbprint(trustStore.trustedCAs);
  const revokedCAs = indexCertificatesByThumbprint(trustStore.revokedCAs);
  if (!trustedCAs.size && !revokedCAs.size) return undefined;
  const warnings: string[] = [...(trustStore.warnings ?? [])];
  const certificateTrust: AuthenticodeCertificateTrustInfo[] = [];
  for (let certificateIndex = 0; certificateIndex < certificates.length; certificateIndex += 1) {
    const certificate = certificates[certificateIndex];
    if (!certificate) continue;
    try {
      certificateTrust.push(
        createTrustInfo(
          certificateIndex,
          await certificateSha1Thumbprint(certificate),
          trustedCAs,
          revokedCAs
        )
      );
    } catch (error) {
      warnings.push(
        `Certificate ${certificateIndex + 1}: unable to compute SHA-1 thumbprint (${describeError(error)}).`
      );
      certificateTrust.push(createTrustInfo(certificateIndex, undefined, trustedCAs, revokedCAs));
    }
  }
  const mergedWarnings = mergeWarnings(warnings);
  return {
    generatedAt: trustStore.generatedAt,
    ...(trustStore.source ? { source: trustStore.source } : {}),
    certificates: certificateTrust,
    ...(mergedWarnings ? { warnings: mergedWarnings } : {})
  };
};
