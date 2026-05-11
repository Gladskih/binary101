"use strict";

import { bufferToHex } from "../../../binary-utils.js";
import type {
  AuthenticodeCertificateTrustInfo,
  AuthenticodeTrustPolicyInfo
} from "./index.js";
import { Certificate, fromBER } from "./pkijs-runtime.js";
import {
  describeError,
  mergeWarnings,
  normalizeLegacyCertificateSignatureAlgorithm
} from "./pkijs-support.js";
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

type ParsedTrustAnchor = {
  certificate: Certificate;
  source: AuthenticodeTrustStoreCertificate;
  thumbprint: string;
};

// Indexed per policy evaluation to avoid repeating DER decoding for every embedded certificate.
type ParsedTrustAnchorIndex = {
  all: ParsedTrustAnchor[];
  bySubject: Map<string, ParsedTrustAnchor[]>;
};

type TrustAnchorStoreInfo = Pick<
  AuthenticodeCertificateTrustInfo,
  "anchorDerBase64" | "anchorSha1Thumbprint" | "anchorSubject" | "stores"
>;

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

const parseTrustAnchor = (
  certificate: AuthenticodeTrustStoreCertificate
): Certificate | undefined => {
  if (!certificate.derBase64) return undefined;
  const asn1 = fromBER(base64ToArrayBuffer(certificate.derBase64));
  if (asn1.offset === -1 || !asn1.result) return undefined;
  return new Certificate({ schema: asn1.result });
};

const addParsedTrustAnchor = (
  index: ParsedTrustAnchorIndex,
  parsedAnchor: ParsedTrustAnchor
): void => {
  index.all.push(parsedAnchor);
  const subjectKey = parsedAnchor.certificate.subject.toString();
  const subjectAnchors = index.bySubject.get(subjectKey);
  if (subjectAnchors) subjectAnchors.push(parsedAnchor);
  else index.bySubject.set(subjectKey, [parsedAnchor]);
};

const indexTrustAnchors = (
  anchors: ReadonlyMap<string, AuthenticodeTrustStoreCertificate>,
  warnings: string[],
  label: string
): ParsedTrustAnchorIndex => {
  const index: ParsedTrustAnchorIndex = { all: [], bySubject: new Map() };
  for (const [thumbprint, source] of anchors) {
    if (!source.derBase64) continue;
    try {
      const certificate = parseTrustAnchor(source);
      if (!certificate) continue;
      normalizeLegacyCertificateSignatureAlgorithm(certificate);
      addParsedTrustAnchor(index, { certificate, source, thumbprint });
    } catch (error) {
      warnings.push(
        `${label} ${thumbprint}: unable to parse trust anchor ` +
        `(${describeError(error)}).`
      );
    }
  }
  return index;
};

const certificateStoreInfo = (
  certificate: AuthenticodeTrustStoreCertificate,
  anchorSha1Thumbprint: string
): TrustAnchorStoreInfo => ({
  anchorSha1Thumbprint,
  ...(certificate.subject ? { anchorSubject: certificate.subject } : {}),
  ...(certificate.derBase64 ? { anchorDerBase64: certificate.derBase64 } : {}),
  ...(certificate.stores?.length ? { stores: certificate.stores } : {})
});

const verifyTrustAnchor = async (
  certificate: Certificate,
  anchors: ParsedTrustAnchorIndex,
  warnings: string[],
  label: string
): Promise<TrustAnchorStoreInfo | undefined> => {
  normalizeLegacyCertificateSignatureAlgorithm(certificate);
  const subjectAnchors = anchors.bySubject.get(certificate.issuer.toString());
  for (const anchor of subjectAnchors ?? anchors.all) {
    try {
      if (!anchor.certificate.subject.isEqual(certificate.issuer)) continue;
      if (await certificate.verify(anchor.certificate)) {
        return certificateStoreInfo(anchor.source, anchor.thumbprint);
      }
    } catch (error) {
      warnings.push(
        `${label} ${anchor.thumbprint}: unable to evaluate trust anchor ` +
        `(${describeError(error)}).`
      );
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
        ...(revoked.derBase64 ? { derBase64: revoked.derBase64 } : {}),
        ...(revoked.stores?.length ? { stores: revoked.stores } : {})
      };
    }
    const trusted = trustedCAs.get(sha1Thumbprint);
    if (trusted) {
      return {
        certificateIndex,
        status: "trusted",
        sha1Thumbprint,
        ...(trusted.derBase64 ? { derBase64: trusted.derBase64 } : {}),
        ...(trusted.stores?.length ? { stores: trusted.stores } : {})
      };
    }
    return { certificateIndex, status: "unknown", sha1Thumbprint };
  }
  return { certificateIndex, status: "unknown" };
};

const resolveUnknownCertificateTrust = async (
  certificate: Certificate,
  directTrust: AuthenticodeCertificateTrustInfo,
  warnings: string[],
  getRevokedAnchorIndex: () => ParsedTrustAnchorIndex,
  getTrustedAnchorIndex: () => ParsedTrustAnchorIndex
): Promise<AuthenticodeCertificateTrustInfo> => {
  const revokedAnchor = await verifyTrustAnchor(
    certificate,
    getRevokedAnchorIndex(),
    warnings,
    "Disallowed CA"
  );
  if (revokedAnchor) return { ...directTrust, status: "revoked", ...revokedAnchor };
  const trustedAnchor = await verifyTrustAnchor(
    certificate,
    getTrustedAnchorIndex(),
    warnings,
    "Trusted CA"
  );
  return trustedAnchor ? { ...directTrust, status: "trusted", ...trustedAnchor } : directTrust;
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
  let trustedAnchorIndex: ParsedTrustAnchorIndex | undefined;
  let revokedAnchorIndex: ParsedTrustAnchorIndex | undefined;
  const getTrustedAnchorIndex = (): ParsedTrustAnchorIndex => {
    trustedAnchorIndex ??= indexTrustAnchors(trustedCAs, warnings, "Trusted CA");
    return trustedAnchorIndex;
  };
  const getRevokedAnchorIndex = (): ParsedTrustAnchorIndex => {
    revokedAnchorIndex ??= indexTrustAnchors(revokedCAs, warnings, "Disallowed CA");
    return revokedAnchorIndex;
  };
  for (let certificateIndex = 0; certificateIndex < certificates.length; certificateIndex += 1) {
    const certificate = certificates[certificateIndex];
    if (!certificate) continue;
    try {
      const sha1Thumbprint = await certificateSha1Thumbprint(certificate);
      const directTrust = createTrustInfo(
        certificateIndex,
        sha1Thumbprint,
        trustedCAs,
        revokedCAs
      );
      if (directTrust.status !== "unknown") {
        certificateTrust.push(directTrust);
        continue;
      }
      certificateTrust.push(
        await resolveUnknownCertificateTrust(
          certificate,
          directTrust,
          warnings,
          getRevokedAnchorIndex,
          getTrustedAnchorIndex
        )
      );
    } catch (error) {
      warnings.push(
        `Certificate ${certificateIndex + 1}: unable to compute SHA-1 thumbprint ` +
        `(${describeError(error)}).`
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
