"use strict";

import { bufferToHex } from "../../../binary-utils.js";
import type { AuthenticodeVerificationCheck } from "./index.js";
import type { Certificate } from "./pkijs-runtime.js";
import { BasicConstraints, ExtKeyUsage } from "./pkijs-runtime.js";
import { addCheck, getByteView, parseIsoDate } from "./pkijs-support.js";
import {
  chooseBestIssuerCandidate,
  verifyCertificateSignature
} from "./pkijs-path-selection.js";

const KEY_USAGE_EXTENSION_OID = "2.5.29.15";
const BASIC_CONSTRAINTS_EXTENSION_OID = "2.5.29.19";
const EXTENDED_KEY_USAGE_EXTENSION_OID = "2.5.29.37";
const KEY_USAGE_DIGITAL_SIGNATURE = 0x80;
const KEY_USAGE_NON_REPUDIATION = 0x40;
const KEY_USAGE_KEY_CERT_SIGN = 0x04;

const readKeyUsage = (certificate: Certificate): Uint8Array | undefined => {
  const extension = certificate.extensions?.find(item => item.extnID === KEY_USAGE_EXTENSION_OID);
  return extension ? getByteView(extension.parsedValue) : undefined;
};

const readExtendedKeyUsage = (certificate: Certificate): string[] | undefined => {
  const extension = certificate.extensions?.find(item => item.extnID === EXTENDED_KEY_USAGE_EXTENSION_OID);
  if (!extension?.parsedValue) return undefined;
  if (extension.parsedValue instanceof ExtKeyUsage) return extension.parsedValue.keyPurposes;
  const purposes = (extension.parsedValue as { keyPurposes?: unknown }).keyPurposes;
  return Array.isArray(purposes) ? purposes.filter((value): value is string => typeof value === "string") : undefined;
};

const readBasicConstraints = (certificate: Certificate): BasicConstraints | undefined => {
  const extension = certificate.extensions?.find(item => item.extnID === BASIC_CONSTRAINTS_EXTENSION_OID);
  if (!extension?.parsedValue) return undefined;
  if (extension.parsedValue instanceof BasicConstraints) return extension.parsedValue;
  const parsed = extension.parsedValue as { cA?: unknown };
  return typeof parsed.cA === "boolean" ? new BasicConstraints({ cA: parsed.cA }) : undefined;
};

const addValidityCheck = (
  checks: AuthenticodeVerificationCheck[],
  id: string,
  title: string,
  certificate: Certificate,
  instant: Date,
  label: string
): void => {
  const valid =
    certificate.notBefore.value.getTime() <= instant.getTime() &&
    certificate.notAfter.value.getTime() >= instant.getTime();
  addCheck(
    checks,
    id,
    valid ? "pass" : "fail",
    title,
    `${label}: ${certificate.notBefore.value.toISOString()} -> ${certificate.notAfter.value.toISOString()}`
  );
};

export const addSigningKeyUsageCheck = (
  checks: AuthenticodeVerificationCheck[],
  id: string,
  title: string,
  certificate: Certificate
): void => {
  const keyUsage = readKeyUsage(certificate);
  if (!keyUsage?.length) {
    addCheck(checks, id, "unknown", title, "Key Usage extension is absent.");
    return;
  }
  const firstByte = keyUsage[0] ?? 0;
  const allowed =
    (firstByte & KEY_USAGE_DIGITAL_SIGNATURE) === KEY_USAGE_DIGITAL_SIGNATURE ||
    (firstByte & KEY_USAGE_NON_REPUDIATION) === KEY_USAGE_NON_REPUDIATION;
  addCheck(checks, id, allowed ? "pass" : "fail", title, `Key Usage bits: ${bufferToHex(keyUsage)}`);
};

export const addExtendedKeyUsageCheck = (
  checks: AuthenticodeVerificationCheck[],
  id: string,
  title: string,
  certificate: Certificate,
  expectedPurposeOid: string,
  missingDetail: string
): void => {
  const keyPurposes = readExtendedKeyUsage(certificate);
  if (!keyPurposes?.length) {
    addCheck(checks, id, "unknown", title, missingDetail);
    return;
  }
  addCheck(
    checks,
    id,
    keyPurposes.includes(expectedPurposeOid) ? "pass" : "fail",
    title,
    `EKU OIDs: ${keyPurposes.join(", ")}`
  );
};

const addIssuerCapabilityChecks = (
  checks: AuthenticodeVerificationCheck[],
  signerLabel: string,
  childIndex: number,
  issuerIndex: number,
  issuerCertificate: Certificate
): void => {
  const basicConstraints = readBasicConstraints(issuerCertificate);
  addCheck(
    checks,
    `${signerLabel}-issuer-${childIndex + 1}-${issuerIndex + 1}-ca`,
    basicConstraints ? (basicConstraints.cA ? "pass" : "fail") : "unknown",
    `${signerLabel}: certificate ${issuerIndex + 1} is marked as a CA for certificate ${childIndex + 1}`,
    basicConstraints ? `basicConstraints.cA = ${String(basicConstraints.cA)}` : "Basic Constraints extension is absent."
  );
  const keyUsage = readKeyUsage(issuerCertificate);
  if (!keyUsage?.length) {
    addCheck(
      checks,
      `${signerLabel}-issuer-${childIndex + 1}-${issuerIndex + 1}-keyusage`,
      "unknown",
      `${signerLabel}: certificate ${issuerIndex + 1} can sign certificate ${childIndex + 1}`,
      "Key Usage extension is absent."
    );
    return;
  }
  const firstByte = keyUsage[0] ?? 0;
  addCheck(
    checks,
    `${signerLabel}-issuer-${childIndex + 1}-${issuerIndex + 1}-keyusage`,
    (firstByte & KEY_USAGE_KEY_CERT_SIGN) === KEY_USAGE_KEY_CERT_SIGN ? "pass" : "fail",
    `${signerLabel}: certificate ${issuerIndex + 1} can sign certificate ${childIndex + 1}`,
    `Key Usage bits: ${bufferToHex(keyUsage)}`
  );
};

export const attachPathChecks = async (
  checks: AuthenticodeVerificationCheck[],
  signerLabel: string,
  certificates: Certificate[],
  leafIndex: number,
  referenceTime: string | undefined,
  referenceLabel: string
): Promise<number[]> => {
  const pathIndexes: number[] = [];
  const visited = new Set<number>();
  const referenceDate = parseIsoDate(referenceTime);
  let currentIndex: number | undefined = leafIndex;
  while (currentIndex != null && !visited.has(currentIndex) && pathIndexes.length <= certificates.length) {
    pathIndexes.push(currentIndex);
    visited.add(currentIndex);
    const currentCertificate = certificates[currentIndex];
    if (!currentCertificate) break;
    addValidityCheck(
      checks,
      `${signerLabel}-certificate-${currentIndex + 1}-current-validity`,
      `${signerLabel}: certificate ${currentIndex + 1} is currently valid`,
      currentCertificate,
      new Date(),
      "Current time"
    );
    if (referenceDate) {
      addValidityCheck(
        checks,
        `${signerLabel}-certificate-${currentIndex + 1}-${referenceLabel}-validity`,
        `${signerLabel}: certificate ${currentIndex + 1} was valid at ${referenceLabel}`,
        currentCertificate,
        referenceDate,
        referenceTime || referenceLabel
      );
    }
    if (currentCertificate.subject.isEqual(currentCertificate.issuer)) {
      const selfSignature = await verifyCertificateSignature(currentCertificate);
      addCheck(
        checks,
        `${signerLabel}-certificate-${currentIndex + 1}-self-signed`,
        selfSignature.status,
        `${signerLabel}: certificate ${currentIndex + 1} self-signature verifies`,
        selfSignature.detail
      );
      break;
    }
    const issuerIndexes = certificates
      .map((certificate, index) => ({ certificate, index }))
      .filter(
        item =>
          !!item.certificate &&
          !visited.has(item.index) &&
          currentCertificate.issuer.isEqual(item.certificate.subject)
      )
      .map(item => item.index);
    if (!issuerIndexes.length) {
      addCheck(
        checks,
        `${signerLabel}-certificate-${currentIndex + 1}-issuer-match`,
        "unknown",
        `${signerLabel}: certificate ${currentIndex + 1} issuer is present in the embedded chain`,
        "No presented issuer certificate matches the issuer DN."
      );
      break;
    }
    const issuerCandidate = await chooseBestIssuerCandidate(
      certificates,
      issuerIndexes,
      currentCertificate,
      visited
    );
    const nextIndex: number = issuerCandidate?.index ?? currentIndex;
    const signatureStatus = issuerCandidate?.signatureStatus ?? {
      status: "unknown",
      detail: "Issuer candidate was not evaluated."
    };
    addCheck(
      checks,
      `${signerLabel}-certificate-${currentIndex + 1}-issuer-match`,
      "pass",
      `${signerLabel}: certificate ${currentIndex + 1} issuer matches certificate ${nextIndex + 1} subject`
    );
    addCheck(
      checks,
      `${signerLabel}-certificate-${currentIndex + 1}-issuer-signature`,
      signatureStatus.status,
      `${signerLabel}: certificate ${currentIndex + 1} signature verifies under certificate ${nextIndex + 1}`,
      signatureStatus.detail
    );
    const nextCertificate = certificates[nextIndex];
    if (!nextCertificate) break;
    addIssuerCapabilityChecks(checks, signerLabel, currentIndex, nextIndex, nextCertificate);
    currentIndex = nextIndex;
  }
  return pathIndexes;
};
