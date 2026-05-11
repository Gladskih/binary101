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
import { evaluateAuthenticodeTrustPolicy } from "./trust-policy.js";
import {
  CODE_SIGNING_EKU_OID,
  addCheck,
  describeError,
  getSigningTime,
  matchSignerCertificate,
  mergeWarnings,
  normalizeLegacyCertificateSignatureAlgorithm,
  normalizeLegacySignatureAlgorithm,
  parseIsoDate,
  toArrayBuffer
} from "./pkijs-support.js";

type VerificationSummary = Pick<
  AuthenticodeVerificationInfo,
  "checks" | "signerVerifications" | "trustPolicy" | "warnings"
>;

const verifySigner = async (
  signedData: SignedData,
  signerIndex: number
): Promise<AuthenticodeSignerVerificationInfo> => {
  try {
    normalizeLegacySignatureAlgorithm(signedData.signerInfos[signerIndex]?.signatureAlgorithm);
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
  for (let signerIndex = 0; signerIndex < signedData.signerInfos.length; signerIndex += 1) {
    const signer = signedData.signerInfos[signerIndex];
    if (!signer) continue;
    const signerLabel = `Signer ${signerIndex + 1}`;
    const signerVerification = await verifySigner(signedData, signerIndex);
    const signerCertificateIndex = await matchSignerCertificate(signer, certificates);
    const signerCertificate =
      signerCertificateIndex != null && signerCertificateIndex >= 0
        ? certificates[signerCertificateIndex]
        : undefined;
    const embeddedSignerCertificateIndex = signerCertificateIndex;
    const signingTime = getSigningTime(signer);
    const signerCertificateLabel =
      embeddedSignerCertificateIndex != null
        ? `Certificate ${embeddedSignerCertificateIndex + 1}`
        : "No embedded certificate matches the signer identifier.";

    if (signerCertificateIndex != null && signerCertificateIndex >= 0) {
      signerVerification.signerCertificateIndex = signerCertificateIndex;
    }
    if (signingTime) {
      signerVerification.signingTime = signingTime;
    }

    addCheck(
      checks,
      `${signerLabel}-certificate`,
      signerCertificate ? "pass" : "fail",
      `${signerLabel}: signer certificate is present in the embedded chain`,
      signerCertificateLabel
    );
    addCheck(
      checks,
      `${signerLabel}-signature`,
      signerVerification.signatureVerified === true ? "pass" : signerVerification.signatureVerified === false ? "fail" : "unknown",
      `${signerLabel}: CMS signature verifies`,
      signerVerification.message
    );
    if (signerVerification.signatureVerified !== true && signerVerification.message) {
      warnings.push(`${signerLabel}: ${signerVerification.message}`);
    }

    const countersignatures = await readCountersignatures(signerLabel, signer, certificates, checks, warnings);
    if (countersignatures?.length) {
      signerVerification.countersignatures = countersignatures;
      const signerDate = parseIsoDate(signingTime);
      countersignatures.forEach(countersignature => {
        const counterDate = parseIsoDate(countersignature.signingTime);
        addCheck(
          checks,
          `${signerLabel}-countersignature-${countersignature.index + 1}-chronology`,
          signerDate && counterDate ? (signerDate.getTime() <= counterDate.getTime() ? "pass" : "fail") : "unknown",
          `${signerLabel}: countersignature ${countersignature.index + 1} is not earlier than the claimed signing time`,
          signingTime && countersignature.signingTime ? `${signingTime} <= ${countersignature.signingTime}` : "One of the signing times is absent."
        );
      });
    }
    const timestampTokens = await readRfc3161TimestampTokens(
      signerLabel,
      signer,
      checks,
      warnings,
      trustStore
    );
    if (timestampTokens?.length) {
      signerVerification.timestampTokens = timestampTokens;
    }
    if (embeddedSignerCertificateIndex != null && signerCertificate) {
      addSigningKeyUsageCheck(
        checks,
        `${signerLabel}-key-usage`,
        `${signerLabel}: certificate permits digital signatures`,
        signerCertificate
      );
      addExtendedKeyUsageCheck(
        checks,
        `${signerLabel}-eku`,
        `${signerLabel}: certificate permits code signing`,
        signerCertificate,
        CODE_SIGNING_EKU_OID,
        "Extended Key Usage extension is absent."
      );
      const certificatePathIndexes = await attachTimestampPathChecks(
        checks,
        signerLabel,
        certificates,
        embeddedSignerCertificateIndex,
        getSignerTimestampReferenceTime(signerVerification)
      );
      if (certificatePathIndexes.length) {
        signerVerification.certificatePathIndexes = certificatePathIndexes;
      }
    }
    signerVerifications.push(signerVerification);
  }

  const mergedWarnings = mergeWarnings(warnings);
  const trustPolicy = await evaluateAuthenticodeTrustPolicy(certificates, trustStore);
  return {
    ...(checks.length ? { checks } : {}),
    ...(signerVerifications.length ? { signerVerifications } : {}),
    ...(trustPolicy ? { trustPolicy } : {}),
    ...(mergedWarnings ? { warnings: mergedWarnings } : {})
  };
};
