"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { AuthenticodeInfo, AuthenticodeTrustGap, AuthenticodeVerificationCheck } from "./index.js";
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
      "This analyzer does not fetch or validate CRL, OCSP, or Microsoft-specific revocation data for any certificate in the chain."
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
    title: "Trusted timestamp authority",
    detail:
      "Countersignature cryptography can be checked locally, but the timestamping chain is not anchored to a trusted TSA root and is not revocation-checked."
  }
];

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

export const verifyAuthenticode = async (
  reader: FileRangeReader,
  core: PeAuthenticodeBestEffortCore | PeAuthenticodeParsedCore,
  securityDir: PeDataDirectory | undefined,
  auth: AuthenticodeInfo,
  payload: Uint8Array,
  digestFunction?: DigestFunction,
  getComputedDigest?: DigestLookup
): Promise<NonNullable<AuthenticodeInfo["verification"]>> => {
  const warnings: string[] = [];
  const verification: NonNullable<AuthenticodeInfo["verification"]> = { trustGaps: TRUST_GAPS };
  const checks: AuthenticodeVerificationCheck[] = [];

  const signatureVerification = await verifyPkcs7Signatures(payload);
  if (signatureVerification.checks?.length) checks.push(...signatureVerification.checks);
  if (signatureVerification.signerVerifications?.length) {
    verification.signerVerifications = signatureVerification.signerVerifications;
  }
  if (signatureVerification.warnings?.length) warnings.push(...signatureVerification.warnings);

  const digestVerification = await verifyAuthenticodeFileDigest(
    reader,
    core,
    securityDir,
    auth,
    digestFunction,
    getComputedDigest
  );
  if (digestVerification.computedFileDigest) {
    verification.computedFileDigest = digestVerification.computedFileDigest;
  }
  if (digestVerification.fileDigestMatches != null) {
    verification.fileDigestMatches = digestVerification.fileDigestMatches;
  }
  checks.unshift(createDigestCheck(auth, digestVerification));
  if (digestVerification.warnings?.length) warnings.push(...digestVerification.warnings);

  if (checks.length) verification.checks = checks;
  const mergedWarnings = mergeWarnings(warnings);
  return mergedWarnings ? { ...verification, warnings: mergedWarnings } : verification;
};
