"use strict";

import { bufferToHex } from "../../../binary-utils.js";
import { computeDigest } from "./digest-algorithms.js";
import type { AuthenticodeTimestampTokenInfo, AuthenticodeVerificationCheck, X509CertificateInfo } from "./index.js";
import type { AuthenticodeTrustStoreSnapshot } from "./trust-store.js";
import type { SignerInfo } from "./pkijs-runtime.js";
import {
  Certificate,
  ContentInfo,
  SignedData,
  TSTInfo,
  id_eContentType_TSTInfo
} from "./pkijs-runtime.js";
import { addExtendedKeyUsageCheck, addSigningKeyUsageCheck, attachTimestampPathChecks } from "./pkijs-path.js";
import { evaluateAuthenticodeTrustPolicy } from "./trust-policy.js";
import {
  TIME_STAMPING_EKU_OID,
  addCheck,
  describeError,
  equalBytes,
  getByteView,
  matchSignerCertificate,
  normalizeLegacyCertificateSignatureAlgorithm,
  normalizeLegacySignatureAlgorithm,
  readOctetStringBytes,
  resolveDigestAlgorithm,
  toArrayBuffer
} from "./pkijs-support.js";
import { verifySignedDataSignerWithLocalRsa } from "./pkijs-local-rsa.js";

// Microsoft Authenticode stores RFC 3161 timestamp tokens in this unsigned attribute.
// RFC 3161 section 2.4.2 defines TimeStampToken as CMS ContentInfo/SignedData.
const AUTHENTICODE_RFC3161_TIMESTAMP_OID = "1.3.6.1.4.1.311.3.3.1";

const NAME_OID_KEYS: Record<string, string> = {
  "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L",
  "2.5.4.8": "S", "2.5.4.10": "O", "2.5.4.11": "OU"
};

const asDerBytes = (value: unknown): Uint8Array | undefined => {
  const encoder = (value as { toBER?: (encodeFlag?: boolean) => ArrayBuffer } | null)?.toBER;
  return typeof encoder === "function" ? new Uint8Array(encoder.call(value, false)) : undefined;
};

const asSchemaDerBytes = (value: unknown): Uint8Array | undefined => {
  const schema = (value as { toSchema?: () => unknown } | null)?.toSchema?.();
  return asDerBytes(schema);
};

const bytesToBase64 = (bytes: Uint8Array): string => {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
};

const formatName = (name: Certificate["subject"] | undefined): string | undefined => {
  const values = name?.typesAndValues
    .map(item => {
      const text = String(item.value?.valueBlock?.value ?? item.value?.toString?.() ?? "");
      return text ? `${NAME_OID_KEYS[item.type] || item.type}=${text}` : "";
    })
    .filter(Boolean);
  return values?.length ? values.join(", ") : undefined;
};

const describeCertificate = (certificate: Certificate): X509CertificateInfo => {
  const info: X509CertificateInfo = {};
  const subject = formatName(certificate.subject);
  const issuer = formatName(certificate.issuer);
  const serialNumber = getByteView(certificate.serialNumber);
  const derBytes = asSchemaDerBytes(certificate);
  if (subject) info.subject = subject;
  if (issuer) info.issuer = issuer;
  if (serialNumber) info.serialNumber = bufferToHex(serialNumber);
  if (Number.isFinite(certificate.notBefore.value.getTime())) {
    info.notBefore = certificate.notBefore.value.toISOString();
  }
  if (Number.isFinite(certificate.notAfter.value.getTime())) {
    info.notAfter = certificate.notAfter.value.toISOString();
  }
  if (derBytes?.length) info.derBase64 = bytesToBase64(derBytes);
  return info;
};

const readTimestampInfo = (signedData: SignedData): TSTInfo | undefined => {
  if (signedData.encapContentInfo.eContentType !== id_eContentType_TSTInfo) return undefined;
  const content = readOctetStringBytes(signedData.encapContentInfo.eContent);
  return content?.length ? TSTInfo.fromBER(toArrayBuffer(content)) : undefined;
};

const addMessageImprintCheck = async (
  checks: AuthenticodeVerificationCheck[],
  label: string,
  token: AuthenticodeTimestampTokenInfo,
  timestampInfo: TSTInfo | undefined,
  parentSignatureBytes: Uint8Array
): Promise<void> => {
  const expected = getByteView(timestampInfo?.messageImprint.hashedMessage);
  const shaAlgorithm = timestampInfo
    ? resolveDigestAlgorithm(timestampInfo.messageImprint.hashAlgorithm.algorithmId)
    : undefined;
  if (!expected?.length || !shaAlgorithm) {
    addCheck(
      checks,
      `${label}-message-imprint`,
      "unknown",
      `${label}: TSTInfo messageImprint matches the parent signature`,
      timestampInfo ? "Unsupported or absent messageImprint digest algorithm." : "TSTInfo is absent."
    );
    return;
  }
  const computed = new Uint8Array(
    await computeDigest(shaAlgorithm, toArrayBuffer(parentSignatureBytes))
  );
  token.messageDigestVerified = equalBytes(computed, expected);
  addCheck(
    checks,
    `${label}-message-imprint`,
    token.messageDigestVerified ? "pass" : "fail",
    `${label}: TSTInfo messageImprint matches the parent signature`,
    `Expected ${bufferToHex(expected)}, computed ${bufferToHex(computed)}`
  );
};

const addTimestampSignatureCheck = async (
  label: string,
  signedData: SignedData,
  parentSignatureBytes: Uint8Array,
  timestampSigner: SignerInfo | undefined,
  signerCertificate: Certificate | undefined,
  token: AuthenticodeTimestampTokenInfo,
  checks: AuthenticodeVerificationCheck[],
  warnings: string[]
): Promise<void> => {
  try {
    const localResult = timestampSigner && signerCertificate
      ? await verifySignedDataSignerWithLocalRsa(signedData, timestampSigner, signerCertificate, parentSignatureBytes)
      : undefined;
    if (localResult) {
      if (localResult.signatureVerified != null) token.signatureVerified = localResult.signatureVerified;
      if (localResult.message) token.message = localResult.message;
      addCheck(
        checks,
        `${label}-signature`,
        localResult.signatureVerified == null ? "unknown" : localResult.signatureVerified ? "pass" : "fail",
        `${label}: CMS signature verifies`,
        localResult.message
      );
      if (localResult.signatureVerified !== true && localResult.message) {
        warnings.push(`${label}: ${localResult.message}`);
      }
      return;
    }
    await signedData.verify({
      signer: 0,
      data: toArrayBuffer(parentSignatureBytes),
      checkChain: false,
      extendedMode: true
    });
    token.signatureVerified = true;
    addCheck(checks, `${label}-signature`, "pass", `${label}: CMS signature verifies`);
  } catch (error) {
    token.signatureVerified = false;
    token.message = describeError(error);
    addCheck(checks, `${label}-signature`, "fail", `${label}: CMS signature verifies`, token.message);
    warnings.push(`${label}: ${token.message}`);
  }
};

const verifyTimestampToken = async (
  signerLabel: string,
  tokenIndex: number,
  value: unknown,
  parentSignatureBytes: Uint8Array,
  checks: AuthenticodeVerificationCheck[],
  warnings: string[],
  trustStore: AuthenticodeTrustStoreSnapshot | undefined
): Promise<AuthenticodeTimestampTokenInfo> => {
  const label = `${signerLabel} RFC3161 timestamp ${tokenIndex + 1}`;
  const token: AuthenticodeTimestampTokenInfo = { index: tokenIndex };
  const bytes = asDerBytes(value);
  if (!bytes?.length) {
    token.message = "Timestamp token is not DER encodable.";
    addCheck(checks, `${label}-parse`, "unknown", `${label}: token structure parsed`, token.message);
    return token;
  }
  const signedData = new SignedData({ schema: ContentInfo.fromBER(toArrayBuffer(bytes)).content });
  signedData.signerInfos.forEach(signer => normalizeLegacySignatureAlgorithm(signer.signatureAlgorithm));
  const certificates = (signedData.certificates ?? []).filter(
    (certificate): certificate is Certificate => certificate instanceof Certificate
  );
  certificates.forEach(normalizeLegacyCertificateSignatureAlgorithm);
  const timestampInfo = readTimestampInfo(signedData);
  if (timestampInfo) token.signingTime = timestampInfo.genTime.toISOString();
  await addMessageImprintCheck(checks, label, token, timestampInfo, parentSignatureBytes);
  const timestampSigner = signedData.signerInfos[0] as SignerInfo | undefined;
  const signerCertificateIndex = timestampSigner
    ? await matchSignerCertificate(timestampSigner, certificates)
    : undefined;
  const timestampSignerCertificateIndex =
    signerCertificateIndex != null && signerCertificateIndex >= 0
      ? signerCertificateIndex
      : undefined;
  const signerCertificate =
    timestampSignerCertificateIndex != null ? certificates[timestampSignerCertificateIndex] : undefined;
  await addTimestampSignatureCheck(
    label,
    signedData,
    parentSignatureBytes,
    timestampSigner,
    signerCertificate,
    token,
    checks,
    warnings
  );
  if (certificates.length) token.certificates = certificates.map(describeCertificate);
  const trustPolicy = await evaluateAuthenticodeTrustPolicy(certificates, trustStore);
  if (trustPolicy) token.trustPolicy = trustPolicy;
  if (timestampSignerCertificateIndex != null) token.signerCertificateIndex = timestampSignerCertificateIndex;
  addCheck(
    checks,
    `${label}-certificate`,
    signerCertificate ? "pass" : "fail",
    `${label}: signer certificate is present in the timestamp token`,
    timestampSignerCertificateIndex != null
      ? `Certificate ${timestampSignerCertificateIndex + 1}`
      : "No embedded certificate matches the timestamp signer identifier."
  );
  if (signerCertificate && timestampSignerCertificateIndex != null) {
    addSigningKeyUsageCheck(
      checks,
      `${label}-key-usage`,
      `${label}: certificate permits digital signatures`,
      signerCertificate
    );
    addExtendedKeyUsageCheck(
      checks,
      `${label}-eku`,
      `${label}: certificate permits time stamping`,
      signerCertificate,
      TIME_STAMPING_EKU_OID,
      "Extended Key Usage extension is absent."
    );
    const certificatePathIndexes = await attachTimestampPathChecks(
      checks,
      label,
      certificates,
      timestampSignerCertificateIndex,
      token.signingTime
    );
    if (certificatePathIndexes.length) token.certificatePathIndexes = certificatePathIndexes;
  }
  return token;
};

export const readRfc3161TimestampTokens = async (
  signerLabel: string,
  signer: SignerInfo,
  checks: AuthenticodeVerificationCheck[],
  warnings: string[],
  trustStore?: AuthenticodeTrustStoreSnapshot
): Promise<AuthenticodeTimestampTokenInfo[] | undefined> => {
  const values =
    signer.unsignedAttrs?.attributes.find(
      attribute => attribute.type === AUTHENTICODE_RFC3161_TIMESTAMP_OID
    )?.values ?? [];
  if (!values.length) return undefined;
  const parentSignatureBytes = signer.signature.valueBlock.valueHexView;
  const tokens: AuthenticodeTimestampTokenInfo[] = [];
  for (let index = 0; index < values.length; index += 1) {
    try {
      tokens.push(
        await verifyTimestampToken(
          signerLabel,
          index,
          values[index],
          parentSignatureBytes,
          checks,
          warnings,
          trustStore
        )
      );
    } catch (error) {
      const message = describeError(error);
      addCheck(
        checks,
        `${signerLabel} RFC3161 timestamp ${index + 1}-parse`,
        "unknown",
        `${signerLabel} RFC3161 timestamp ${index + 1}: token structure parsed`,
        message
      );
      warnings.push(`${signerLabel} RFC3161 timestamp ${index + 1}: ${message}`);
    }
  }
  return tokens.length ? tokens : undefined;
};
