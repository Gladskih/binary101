"use strict";

import type {
  AuthenticodeSignerVerificationInfo,
  AuthenticodeVerificationCheck,
  AuthenticodeVerificationInfo
} from "./index.js";
import { Certificate, ContentInfo, SignedData } from "./pkijs-runtime.js";
import { readCountersignatures } from "./pkijs-countersignatures.js";
import { addExtendedKeyUsageCheck, addSigningKeyUsageCheck, attachPathChecks } from "./pkijs-path.js";
import {
  CODE_SIGNING_EKU_OID,
  addCheck,
  describeError,
  getSigningTime,
  matchSignerCertificate,
  mergeWarnings,
  parseIsoDate,
  toArrayBuffer
} from "./pkijs-support.js";

type VerificationSummary = Pick<
  AuthenticodeVerificationInfo,
  "checks" | "signerVerifications" | "warnings"
>;

const verifySigner = async (
  signedData: SignedData,
  signerIndex: number
): Promise<AuthenticodeSignerVerificationInfo> => {
  try {
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

export const verifyPkcs7Signatures = async (payload: Uint8Array): Promise<VerificationSummary> => {
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
      const certificatePathIndexes = await attachPathChecks(
        checks,
        signerLabel,
        certificates,
        embeddedSignerCertificateIndex,
        signingTime,
        "signing time"
      );
      if (certificatePathIndexes.length) {
        signerVerification.certificatePathIndexes = certificatePathIndexes;
      }
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
    signerVerifications.push(signerVerification);
  }

  const mergedWarnings = mergeWarnings(warnings);
  return {
    ...(checks.length ? { checks } : {}),
    ...(signerVerifications.length ? { signerVerifications } : {}),
    ...(mergedWarnings ? { warnings: mergedWarnings } : {})
  };
};
