"use strict";

import type {
  AuthenticodeSignerVerificationInfo,
  AuthenticodeVerificationCheck,
  AuthenticodeVerificationInfo
} from "./index.js";
import type { AuthenticodeTrustStoreSnapshot } from "./trust-store.js";
import { Certificate, ContentInfo, SignedData } from "./pkijs-runtime.js";
import { readCountersignatures } from "./pkijs-countersignatures.js";
import { readRfc3161TimestampTokens } from "./pkijs-rfc3161-timestamps.js";
import { addExtendedKeyUsageCheck, addSigningKeyUsageCheck, attachTimestampPathChecks } from "./pkijs-path.js";
import { verifySignedDataSignerWithLocalRsa } from "./pkijs-local-rsa.js";
import { evaluateAuthenticodeTrustPolicy } from "./trust-policy.js";
import {
  CODE_SIGNING_EKU_OID,
  addCheck,
  describeError,
  getSigningTime,
  matchSignerCertificate,
  mergeWarnings,
  normalizeLegacyCertificateSignatureAlgorithm,
  normalizeLegacySignerSignatureAlgorithm,
  parseIsoDate,
  toArrayBuffer
} from "./pkijs-support.js";

type VerificationSummary = Pick<
  AuthenticodeVerificationInfo,
  "checks" | "signerVerifications" | "trustPolicy" | "warnings"
>;

type Pkcs7VerificationState = {
  signedData: SignedData;
  certificates: Certificate[];
  checks: AuthenticodeVerificationCheck[];
  signerVerifications: AuthenticodeSignerVerificationInfo[];
  warnings: string[];
  trustStore?: AuthenticodeTrustStoreSnapshot;
};

const appendCertificatePathWarnings = (
  checks: AuthenticodeVerificationCheck[],
  warnings: string[]
): void => {
  checks.forEach(check => {
    if (
      check.status === "unknown" &&
      check.detail &&
      (check.id.endsWith("-self-signed") || check.id.endsWith("-issuer-signature"))
    ) {
      warnings.push(`${check.title}: ${check.detail}`);
    }
  });
};

const verifySigner = async (
  signedData: SignedData,
  signerIndex: number,
  signerCertificate: Certificate | undefined,
  warnings: string[]
): Promise<AuthenticodeSignerVerificationInfo> => {
  const signer = signedData.signerInfos[signerIndex];
  try {
    const normalizationWarning = normalizeLegacySignerSignatureAlgorithm(signer);
    if (normalizationWarning) warnings.push(`Signer ${signerIndex + 1}: ${normalizationWarning}`);
    if (signer && signerCertificate) {
      const localResult = await verifySignedDataSignerWithLocalRsa(signedData, signer, signerCertificate);
      if (localResult) {
        return {
          index: signerIndex,
          ...(localResult.message ? { message: localResult.message } : {}),
          ...(localResult.signatureVerified != null ? { signatureVerified: localResult.signatureVerified } : {})
        };
      }
    }
    const result = await signedData.verify({ signer: signerIndex, checkChain: false, extendedMode: true });
    return {
      index: signerIndex,
      ...(typeof result.code === "number" ? { code: result.code } : {}),
      ...(result.message ? { message: result.message } : {}),
      ...(typeof result.signatureVerified === "boolean" ? { signatureVerified: result.signatureVerified } : {}),
      ...(typeof result.signerCertificateVerified === "boolean" ? { signerCertificateVerified: result.signerCertificateVerified } : {})
    };
  } catch (error) {
    const result = error as Partial<AuthenticodeSignerVerificationInfo>;
    return {
      index: signerIndex,
      ...(typeof result.code === "number" ? { code: result.code } : {}),
      message: describeError(error),
      ...(typeof result.signatureVerified === "boolean" ? { signatureVerified: result.signatureVerified } : {}),
      ...(typeof result.signerCertificateVerified === "boolean" ? { signerCertificateVerified: result.signerCertificateVerified } : {})
    };
  }
};

const getSignerTimestampReferenceTime = (
  signerVerification: AuthenticodeSignerVerificationInfo
): string | undefined => [
  ...(signerVerification.countersignatures
    ?.filter(counter => counter.signatureVerified && counter.messageDigestVerified && counter.signingTime)
    .map(counter => counter.signingTime as string) ?? []),
  ...(signerVerification.timestampTokens
    ?.filter(token => token.signatureVerified && token.messageDigestVerified && token.signingTime)
    .map(token => token.signingTime as string) ?? [])
].sort()[0];

const addCountersignatureChronologyChecks = (
  checks: AuthenticodeVerificationCheck[],
  signerLabel: string,
  signingTime: string | undefined,
  signerVerification: AuthenticodeSignerVerificationInfo
): void => {
  const signerDate = parseIsoDate(signingTime);
  signerVerification.countersignatures?.forEach(countersignature => {
    const counterDate = parseIsoDate(countersignature.signingTime);
    addCheck(
      checks,
      `${signerLabel}-countersignature-${countersignature.index + 1}-chronology`,
      signerDate && counterDate ? (signerDate.getTime() <= counterDate.getTime() ? "pass" : "fail") : "unknown",
      `${signerLabel}: countersignature ${countersignature.index + 1} is not earlier than the claimed signing time`,
      signingTime && countersignature.signingTime ? `${signingTime} <= ${countersignature.signingTime}` : "One of the signing times is absent."
    );
  });
};

const addSignerCertificateChecks = async (
  state: Pkcs7VerificationState,
  signerLabel: string,
  signerCertificate: Certificate,
  embeddedSignerCertificateIndex: number,
  signerVerification: AuthenticodeSignerVerificationInfo
): Promise<void> => {
  addSigningKeyUsageCheck(
    state.checks,
    `${signerLabel}-key-usage`,
    `${signerLabel}: certificate permits digital signatures`,
    signerCertificate
  );
  addExtendedKeyUsageCheck(
    state.checks,
    `${signerLabel}-eku`,
    `${signerLabel}: certificate permits code signing`,
    signerCertificate,
    CODE_SIGNING_EKU_OID,
    "Extended Key Usage extension is absent."
  );
  const certificatePathIndexes = await attachTimestampPathChecks(
    state.checks,
    signerLabel,
    state.certificates,
    embeddedSignerCertificateIndex,
    getSignerTimestampReferenceTime(signerVerification)
  );
  if (certificatePathIndexes.length) signerVerification.certificatePathIndexes = certificatePathIndexes;
};

const verifyPkcs7Signer = async (state: Pkcs7VerificationState, signerIndex: number): Promise<void> => {
  const signer = state.signedData.signerInfos[signerIndex];
  if (!signer) return;
  const signerLabel = `Signer ${signerIndex + 1}`;
  const signerCertificateIndex = await matchSignerCertificate(signer, state.certificates);
  const signerCertificate =
    signerCertificateIndex != null && signerCertificateIndex >= 0
      ? state.certificates[signerCertificateIndex]
      : undefined;
  const signerVerification = await verifySigner(
    state.signedData,
    signerIndex,
    signerCertificate,
    state.warnings
  );
  const embeddedSignerCertificateIndex = signerCertificateIndex;
  const signingTime = getSigningTime(signer);
  const signerCertificateLabel =
    embeddedSignerCertificateIndex != null
      ? `Certificate ${embeddedSignerCertificateIndex + 1}`
      : "No embedded certificate matches the signer identifier.";
  if (signerCertificateIndex != null && signerCertificateIndex >= 0) {
    signerVerification.signerCertificateIndex = signerCertificateIndex;
  }
  if (signingTime) signerVerification.signingTime = signingTime;
  addCheck(
    state.checks,
    `${signerLabel}-certificate`,
    signerCertificate ? "pass" : "fail",
    `${signerLabel}: signer certificate is present in the embedded chain`,
    signerCertificateLabel
  );
  addCheck(
    state.checks,
    `${signerLabel}-signature`,
    signerVerification.signatureVerified === true ? "pass" : signerVerification.signatureVerified === false ? "fail" : "unknown",
    `${signerLabel}: CMS signature verifies`,
    signerVerification.message
  );
  if (signerVerification.signatureVerified !== true && signerVerification.message) {
    state.warnings.push(`${signerLabel}: ${signerVerification.message}`);
  }
  const countersignatures = await readCountersignatures(
    signerLabel, signer, state.certificates, state.checks, state.warnings
  );
  if (countersignatures?.length) {
    signerVerification.countersignatures = countersignatures;
    addCountersignatureChronologyChecks(state.checks, signerLabel, signingTime, signerVerification);
  }
  const timestampTokens = await readRfc3161TimestampTokens(
    signerLabel,
    signer,
    state.checks,
    state.warnings,
    state.trustStore
  );
  if (timestampTokens?.length) signerVerification.timestampTokens = timestampTokens;
  if (embeddedSignerCertificateIndex != null && signerCertificate) {
    await addSignerCertificateChecks(
      state, signerLabel, signerCertificate, embeddedSignerCertificateIndex, signerVerification
    );
  }
  state.signerVerifications.push(signerVerification);
};

export const verifyPkcs7Signatures = async (
  payload: Uint8Array,
  trustStore?: AuthenticodeTrustStoreSnapshot
): Promise<VerificationSummary> => {
  const checks: AuthenticodeVerificationCheck[] = [];
  const signerVerifications: AuthenticodeSignerVerificationInfo[] = [];
  const warnings: string[] = [];

  let signedData: SignedData;
  try {
    const contentInfo = ContentInfo.fromBER(toArrayBuffer(payload));
    signedData = new SignedData({ schema: contentInfo.content });
  } catch (error) {
    return { warnings: [`Unable to decode CMS ContentInfo: ${describeError(error)}`] };
  }

  const certificates = (signedData.certificates ?? []).filter(
    (certificate): certificate is Certificate => certificate instanceof Certificate
  );
  certificates.forEach(normalizeLegacyCertificateSignatureAlgorithm);
  const state: Pkcs7VerificationState = {
    signedData,
    certificates,
    checks,
    signerVerifications,
    warnings,
    ...(trustStore ? { trustStore } : {})
  };
  for (let signerIndex = 0; signerIndex < signedData.signerInfos.length; signerIndex += 1) {
    await verifyPkcs7Signer(state, signerIndex);
  }

  appendCertificatePathWarnings(checks, warnings);
  const mergedWarnings = mergeWarnings(warnings);
  const trustPolicy = await evaluateAuthenticodeTrustPolicy(certificates, trustStore);
  return {
    ...(checks.length ? { checks } : {}),
    ...(signerVerifications.length ? { signerVerifications } : {}),
    ...(trustPolicy ? { trustPolicy } : {}),
    ...(mergedWarnings ? { warnings: mergedWarnings } : {})
  };
};
