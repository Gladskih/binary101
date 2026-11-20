"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { AuthenticodeInfo, AuthenticodeTrustGap, AuthenticodeVerificationCheck } from "./index.js";
import type { AuthenticodeTrustStoreSnapshot } from "./trust-store.js";
import {
  authenticodeTrustStoreSnapshot,
  hasAuthenticodeTrustStoreData
} from "./trust-store.js";
import {
  computePeAuthenticodeDigest,
  computePeAuthenticodeDigestBestEffort,
  computePeAuthenticodeDigestFromParsedPe,
  type DigestFunction,
  type DigestLookup,
  type PeAuthenticodeBestEffortCore,
  type PeAuthenticodeParsedCore,
  verifyAuthenticodeFileDigest
} from "./digest.js";
import { verifyPkcs7Signatures } from "./pkijs.js";
import { decodePkcs7 } from "./pkcs7.js";
import { ContentInfo } from "./pkijs-runtime.js";
import { mergeWarnings } from "./pkijs-support.js";
import type { PeDataDirectory } from "../types.js";

const TRUST_GAPS: AuthenticodeTrustGap[] = [
  {
    id: "trust-anchor",
    title: "Trusted root / enterprise trust store",
    detail:
      "This analyzer does not anchor the presented chain to the OS/browser trust store or to a locally configured enterprise root set."
  },
  {
    id: "revocation",
    title: "Revocation status",
    detail:
      "This analyzer does not fetch or validate live CRL, OCSP, or Microsoft-specific revocation data for any certificate in the chain."
  },
  {
    id: "missing-intermediates",
    title: "Missing intermediates and AIA retrieval",
    detail:
      "This analyzer only validates certificates embedded in the CMS payload and does not download missing intermediates via AIA or other remote mechanisms."
  },
  {
    id: "platform-policy",
    title: "Platform trust policy",
    detail:
      "This analyzer does not execute WinVerifyTrust / Authenticode policy, catalog lookup, Microsoft root-program rules, or local machine policy."
  },
  {
    id: "timestamp-trust",
    title: "Timestamp authority trust",
    detail:
      "Timestamp countersignatures and RFC3161 tokens are parsed and verified locally, but full TSA trust policy is limited to the bundled local CA snapshot when available, and revocation is not checked."
  }
];

const trustStoreHasAnchors = (trustStore: AuthenticodeTrustStoreSnapshot | undefined): boolean =>
  !!trustStore?.generatedAt && trustStore.trustedCAs.length > 0;

const createTrustGaps = (
  trustStore: AuthenticodeTrustStoreSnapshot | undefined
): AuthenticodeTrustGap[] =>
  trustStoreHasAnchors(trustStore)
    ? TRUST_GAPS.filter(gap => gap.id !== "trust-anchor")
    : TRUST_GAPS;

const createDigestCheck = (
  auth: AuthenticodeInfo,
  digestVerification: Awaited<ReturnType<typeof verifyAuthenticodeFileDigest>>
): AuthenticodeVerificationCheck => {
  if (!auth.fileDigest) {
    return {
      id: "file-digest-missing",
      status: "unknown",
      title: "Embedded file digest is present in the Authenticode payload",
      detail: "SPC_INDIRECT_DATA did not expose a file digest."
    };
  }
  if (digestVerification.fileDigestMatches === true) {
    return {
      id: "file-digest-match",
      status: "pass",
      title: "Embedded file digest matches the computed PE Authenticode digest",
      ...(digestVerification.computedFileDigest ? { detail: digestVerification.computedFileDigest } : {})
    };
  }
  if (digestVerification.fileDigestMatches === false) {
    return {
      id: "file-digest-match",
      status: "fail",
      title: "Embedded file digest matches the computed PE Authenticode digest",
      detail:
        `Embedded ${auth.fileDigest}` +
        (digestVerification.computedFileDigest ? `, computed ${digestVerification.computedFileDigest}` : "")
    };
  }
  return {
    id: "file-digest-match",
    status: "unknown",
    title: "Embedded file digest matches the computed PE Authenticode digest",
    detail: digestVerification.computedFileDigest || "Digest verification did not reach a conclusive pass/fail result."
  };
};

export {
  computePeAuthenticodeDigest,
  computePeAuthenticodeDigestBestEffort,
  computePeAuthenticodeDigestFromParsedPe,
  verifyAuthenticodeFileDigest
};
export type { PeAuthenticodeBestEffortCore, PeAuthenticodeParsedCore };

// Bound the total CMS verifications and the depth of overlapping nested payloads.
const MAX_NESTED_SIGNATURES = 16;
const MAX_NESTED_DEPTH = 4;

const cacheDigestLookup = (compute: DigestLookup): DigestLookup => {
  const digests = new Map<string, Promise<string | null>>();
  return algorithm => {
    const key = typeof algorithm === "string" ? algorithm : algorithm.name;
    const cached = digests.get(key);
    if (cached) return cached;
    const computed = compute(algorithm);
    digests.set(key, computed);
    return computed;
  };
};

export const verifyAuthenticode = (
  reader: FileRangeReader,
  core: PeAuthenticodeBestEffortCore | PeAuthenticodeParsedCore,
  securityDir: PeDataDirectory | undefined,
  auth: AuthenticodeInfo,
  payload: Uint8Array,
  digestFunction?: DigestFunction,
  getComputedDigest?: DigestLookup,
  trustStore?: AuthenticodeTrustStoreSnapshot
): Promise<NonNullable<AuthenticodeInfo["verification"]>> => {
  const digestLookup = getComputedDigest ?? cacheDigestLookup(algorithm =>
    computePeAuthenticodeDigest(reader, core, securityDir, algorithm, digestFunction));
  let remaining = MAX_NESTED_SIGNATURES;
  const verifySignature = async (
    signature: AuthenticodeInfo, bytes: Uint8Array, depth: number
  ): Promise<NonNullable<AuthenticodeInfo["verification"]>> => {
    const { nestedSignaturePayloads, ...cms } = await verifyPkcs7Signatures(bytes, trustStore);
    const warnings = [...(cms.warnings ?? [])];
    const nestedSignatures: NonNullable<NonNullable<AuthenticodeInfo["verification"]>["nestedSignatures"]> = [];
    for (const nested of nestedSignaturePayloads ?? []) {
      if (remaining === 0 || depth === MAX_NESTED_DEPTH) {
        warnings.push("Additional nested signatures exceed the analysis limit.");
        break;
      }
      remaining -= 1;
      const child = decodePkcs7(nested.bytes);
      if (child.contentType !== ContentInfo.SIGNED_DATA) {
        warnings.push(`Signer ${nested.signerIndex + 1}: nested signature is missing SignedData ContentInfo.`);
        continue;
      }
      nestedSignatures.push({ signerIndex: nested.signerIndex, signature: {
        ...child, verification: await verifySignature(child, nested.bytes, depth + 1)
      } });
    }
    const digest = await verifyAuthenticodeFileDigest(reader, core, securityDir, signature,
      undefined, digestLookup);
    const mergedWarnings = mergeWarnings([...warnings, ...(digest.warnings ?? [])]);
    return {
      ...cms,
      ...(digest.computedFileDigest ? { computedFileDigest: digest.computedFileDigest } : {}),
      ...(digest.fileDigestMatches != null ? { fileDigestMatches: digest.fileDigestMatches } : {}),
      checks: [createDigestCheck(signature, digest), ...(cms.checks ?? [])],
      trustGaps: createTrustGaps(trustStore),
      ...(nestedSignatures.length ? { nestedSignatures } : {}),
      ...(mergedWarnings ? { warnings: mergedWarnings } : {})
    };
  };
  return verifySignature(auth, payload, 0);
};

export const verifyAuthenticodeWithBundledTrust = (

  reader: FileRangeReader,
  core: PeAuthenticodeBestEffortCore | PeAuthenticodeParsedCore,
  securityDir: PeDataDirectory | undefined,
  auth: AuthenticodeInfo,
  payload: Uint8Array,
  digestFunction?: DigestFunction,
  getComputedDigest?: DigestLookup
): Promise<NonNullable<AuthenticodeInfo["verification"]>> =>
  verifyAuthenticode(
    reader,
    core,
    securityDir,
    auth,
    payload,
    digestFunction,
    getComputedDigest,
    hasAuthenticodeTrustStoreData(authenticodeTrustStoreSnapshot)
      ? authenticodeTrustStoreSnapshot
      : undefined
  );
