"use strict";

import { bufferToHex } from "../../../binary-utils.js";
import type {
  AuthenticodeCertificateTrustInfo,
  AuthenticodeTrustPolicyInfo
} from "./index.js";
import { Certificate, fromBER } from "./pkijs-runtime.js";
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

const base64ToArrayBuffer = (value: string): ArrayBuffer => {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
};

const parseTrustAnchor = (certificate: AuthenticodeTrustStoreCertificate): Certificate | undefined => {
  if (!certificate.derBase64) return undefined;
  const asn1 = fromBER(base64ToArrayBuffer(certificate.derBase64));
  if (asn1.offset === -1 || !asn1.result) return undefined;
  return new Certificate({ schema: asn1.result });
};

const certificateStoreInfo = (
  certificate: AuthenticodeTrustStoreCertificate,
  anchorSha1Thumbprint: string
): Pick<AuthenticodeCertificateTrustInfo, "anchorSha1Thumbprint" | "anchorSubject" | "stores"> => ({
  anchorSha1Thumbprint,
  ...(certificate.subject ? { anchorSubject: certificate.subject } : {}),
  ...(certificate.stores?.length ? { stores: certificate.stores } : {})
});

const verifyTrustAnchor = async (
  certificate: Certificate,
  anchors: ReadonlyMap<string, AuthenticodeTrustStoreCertificate>,
  warnings: string[],
  label: string
): Promise<Pick<AuthenticodeCertificateTrustInfo, "anchorSha1Thumbprint" | "anchorSubject" | "stores"> | undefined> => {
  for (const [thumbprint, anchor] of anchors) {
    if (!anchor.derBase64) continue;
    try {
      const anchorCertificate = parseTrustAnchor(anchor);
      if (anchorCertificate?.subject.isEqual(certificate.issuer) && await certificate.verify(anchorCertificate)) {
        return certificateStoreInfo(anchor, thumbprint);
      }
    } catch (error) {
      warnings.push(`${label} ${thumbprint}: unable to evaluate trust anchor (${describeError(error)}).`);
    }
  }
  return undefined;
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
      const sha1Thumbprint = await certificateSha1Thumbprint(certificate);
      const directTrust = createTrustInfo(certificateIndex, sha1Thumbprint, trustedCAs, revokedCAs);
      if (directTrust.status !== "unknown") {
        certificateTrust.push(directTrust);
        continue;
      }
      const revokedAnchor = await verifyTrustAnchor(certificate, revokedCAs, warnings, "Disallowed CA");
      if (revokedAnchor) {
        certificateTrust.push({ ...directTrust, status: "revoked", ...revokedAnchor });
        continue;
      }
      const trustedAnchor = await verifyTrustAnchor(certificate, trustedCAs, warnings, "Trusted CA");
      certificateTrust.push(
        trustedAnchor ? { ...directTrust, status: "trusted", ...trustedAnchor } : directTrust
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
