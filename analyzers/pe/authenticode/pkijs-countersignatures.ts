"use strict";

import { bufferToHex } from "../../../binary-utils.js";
import { computeDigest } from "./digest-algorithms.js";
import type {
  AuthenticodeCounterSignatureInfo,
  AuthenticodeVerificationCheck
} from "./index.js";
import type { Certificate } from "./pkijs-runtime.js";
import { SignerInfo, getCrypto } from "./pkijs-runtime.js";
import { addExtendedKeyUsageCheck, addSigningKeyUsageCheck, attachTimestampPathChecks } from "./pkijs-path.js";
import {
  CMS_COUNTERSIGNATURE_OID,
  CMS_MESSAGE_DIGEST_OID,
  RSA_ENCRYPTION_OID,
  TIME_STAMPING_EKU_OID,
  addCheck,
  describeError,
  equalBytes,
  getAttributeValue,
  getByteView,
  getSigningTime,
  matchSignerCertificate,
  normalizeLegacySignatureAlgorithm,
  resolveDigestAlgorithm,
  toArrayBuffer
} from "./pkijs-support.js";
import {
  shouldVerifyRsaPkcs1v15Locally,
  verifyRsaPkcs1v15Signature
} from "./rsa-pkcs1v15.js";

const verifyCountersignature = async (
  signerLabel: string,
  counterIndex: number,
  parentSigner: SignerInfo,
  counterSigner: SignerInfo,
  certificates: Certificate[],
  checks: AuthenticodeVerificationCheck[],
  warnings: string[]
): Promise<AuthenticodeCounterSignatureInfo> => {
  const label = `${signerLabel} countersignature ${counterIndex + 1}`;
  const info: AuthenticodeCounterSignatureInfo = { index: counterIndex };
  const signerCertificateIndex = await matchSignerCertificate(counterSigner, certificates);
  const countersignerCertificate =
    signerCertificateIndex != null && signerCertificateIndex >= 0
      ? certificates[signerCertificateIndex]
      : undefined;
  const embeddedCountersignerCertificateIndex = signerCertificateIndex;
  const signingTime = getSigningTime(counterSigner);
  const countersignerCertificateLabel =
    embeddedCountersignerCertificateIndex != null
      ? `Certificate ${embeddedCountersignerCertificateIndex + 1}`
      : "No embedded certificate matches the countersigner identifier.";
  if (embeddedCountersignerCertificateIndex != null && embeddedCountersignerCertificateIndex >= 0) {
    info.signerCertificateIndex = embeddedCountersignerCertificateIndex;
  }
  if (signingTime) info.signingTime = signingTime;

  addCheck(
    checks,
    `${label}-certificate`,
    countersignerCertificate ? "pass" : "fail",
    `${label}: signer certificate is present in the embedded chain`,
    countersignerCertificateLabel
  );
  if (embeddedCountersignerCertificateIndex == null || !countersignerCertificate) {
    info.message = "Countersigner certificate was not found in the embedded chain.";
    return info;
  }
  await verifyCountersignatureDigest(label, parentSigner, counterSigner, checks, info);
  await verifyCountersignatureSignature(
    label,
    parentSigner,
    counterSigner,
    countersignerCertificate,
    checks,
    warnings,
    info
  );
  const certificatePathIndexes = await attachCountersignatureCertificateChecks(
    label,
    countersignerCertificate,
    certificates,
    embeddedCountersignerCertificateIndex,
    signingTime,
    checks
  );
  if (certificatePathIndexes.length) info.certificatePathIndexes = certificatePathIndexes;
  return info;
};

const verifyCountersignatureDigest = async (
  label: string,
  parentSigner: SignerInfo,
  counterSigner: SignerInfo,
  checks: AuthenticodeVerificationCheck[],
  info: AuthenticodeCounterSignatureInfo
): Promise<void> => {
  const parentSignatureBytes = parentSigner.signature.valueBlock.valueHexView;
  const messageDigestValue = getByteView(getAttributeValue(counterSigner, CMS_MESSAGE_DIGEST_OID));
  if (!messageDigestValue?.length) {
    addCheck(checks, `${label}-message-digest`, "unknown", `${label}: signed attributes message digest matches the parent signature`, "messageDigest signed attribute is absent.");
    return;
  }
  const shaAlgorithm = resolveDigestAlgorithm(counterSigner.digestAlgorithm.algorithmId);
  if (!shaAlgorithm) {
    addCheck(
      checks,
      `${label}-message-digest`,
      "unknown",
      `${label}: signed attributes message digest matches the parent signature`,
      `Unsupported digest algorithm OID ${counterSigner.digestAlgorithm.algorithmId}.`
    );
    return;
  }
  const digestBytes = new Uint8Array(await computeDigest(shaAlgorithm, toArrayBuffer(parentSignatureBytes)));
  const digestMatches = equalBytes(digestBytes, messageDigestValue);
  info.messageDigestVerified = digestMatches;
  addCheck(
    checks,
    `${label}-message-digest`,
    digestMatches ? "pass" : "fail",
    `${label}: signed attributes message digest matches the parent signature`,
    `Expected ${bufferToHex(messageDigestValue)}, computed ${bufferToHex(digestBytes)}`
  );
};

const verifyCountersignatureSignature = async (
  label: string,
  parentSigner: SignerInfo,
  counterSigner: SignerInfo,
  countersignerCertificate: Certificate,
  checks: AuthenticodeVerificationCheck[],
  warnings: string[],
  info: AuthenticodeCounterSignatureInfo
): Promise<void> => {
  const cryptoEngine = getCrypto(true);
  if (!cryptoEngine) {
    addCheck(checks, `${label}-signature`, "unknown", `${label}: CMS signature verifies`, "PKI.js crypto engine is unavailable.");
    info.message = "PKI.js crypto engine is unavailable.";
    return;
  }
  const shaAlgorithm = resolveDigestAlgorithm(counterSigner.digestAlgorithm.algorithmId);
  normalizeLegacySignatureAlgorithm(counterSigner.signatureAlgorithm);
  const verificationData = counterSigner.signedAttrs
    ? counterSigner.signedAttrs.encodedValue
    : toArrayBuffer(parentSigner.signature.valueBlock.valueHexView);
  if (shouldVerifyRsaPkcs1v15Locally(counterSigner.signatureAlgorithm, counterSigner.digestAlgorithm.algorithmId)) {
    const localResult = await verifyRsaPkcs1v15Signature(
      new Uint8Array(verificationData),
      counterSigner.signature.valueBlock.valueHexView,
      countersignerCertificate.subjectPublicKeyInfo,
      counterSigner.signatureAlgorithm,
      counterSigner.digestAlgorithm.algorithmId
    );
    if (localResult) {
      if (localResult.verified != null) info.signatureVerified = localResult.verified;
      addCheck(
        checks,
        `${label}-signature`,
        localResult.verified == null ? "unknown" : localResult.verified ? "pass" : "fail",
        `${label}: CMS signature verifies`,
        localResult.detail
      );
      if (localResult.verified == null && localResult.detail) warnings.push(`${label}: ${localResult.detail}`);
      return;
    }
  }
  try {
    const verified = await cryptoEngine.verifyWithPublicKey(
      verificationData,
      counterSigner.signature,
      countersignerCertificate.subjectPublicKeyInfo,
      counterSigner.signatureAlgorithm,
      counterSigner.signatureAlgorithm.algorithmId === RSA_ENCRYPTION_OID ? shaAlgorithm : undefined
    );
    info.signatureVerified = verified;
    addCheck(checks, `${label}-signature`, verified ? "pass" : "fail", `${label}: CMS signature verifies`);
  } catch (error) {
    const message = describeError(error);
    info.message = message;
    addCheck(checks, `${label}-signature`, "unknown", `${label}: CMS signature verifies`, message);
    warnings.push(`${label}: ${message}`);
  }
};

const attachCountersignatureCertificateChecks = async (
  label: string,
  countersignerCertificate: Certificate,
  certificates: Certificate[],
  embeddedCountersignerCertificateIndex: number,
  signingTime: string | undefined,
  checks: AuthenticodeVerificationCheck[]
): Promise<number[]> => {
  addSigningKeyUsageCheck(checks, `${label}-key-usage`, `${label}: certificate permits digital signatures`, countersignerCertificate);
  addExtendedKeyUsageCheck(
    checks,
    `${label}-eku`,
    `${label}: certificate permits time stamping`,
    countersignerCertificate,
    TIME_STAMPING_EKU_OID,
    "Extended Key Usage extension is absent."
  );
  return attachTimestampPathChecks(checks, label, certificates, embeddedCountersignerCertificateIndex, signingTime);
};

export const readCountersignatures = async (
  signerLabel: string,
  signer: SignerInfo,
  certificates: Certificate[],
  checks: AuthenticodeVerificationCheck[],
  warnings: string[]
): Promise<AuthenticodeCounterSignatureInfo[] | undefined> => {
  const values =
    signer.unsignedAttrs?.attributes.find(attribute => attribute.type === CMS_COUNTERSIGNATURE_OID)?.values ?? [];
  if (!values.length) return undefined;
  const countersignatures: AuthenticodeCounterSignatureInfo[] = [];
  for (let index = 0; index < values.length; index += 1) {
    try {
      countersignatures.push(
        await verifyCountersignature(
          signerLabel,
          index,
          signer,
          new SignerInfo({ schema: values[index] }),
          certificates,
          checks,
          warnings
        )
      );
    } catch (error) {
      const message = describeError(error);
      addCheck(
        checks,
        `${signerLabel}-countersignature-${index + 1}-parse`,
        "unknown",
        `${signerLabel} countersignature ${index + 1}: structure parsed successfully`,
        message
      );
      warnings.push(`${signerLabel} countersignature ${index + 1}: ${message}`);
    }
  }
  return countersignatures.length ? countersignatures : undefined;
};
