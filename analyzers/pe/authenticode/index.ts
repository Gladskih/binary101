"use strict";

import { decodePkcs7 } from "./pkcs7.js";
import { readDerElement, TAG_SEQUENCE } from "./der.js";

// Share documented type codes with the renderer. A type name does not establish payload validity.
// Microsoft WinTrust.h defines X509=1, PKCS_SIGNED_DATA=2 and TS_STACK_SIGNED=4:
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/WinTrust.h
export const WIN_CERTIFICATE_TYPES: ReadonlyArray<{
  code: number;
  name: string;
  label: string;
  description: string;
}> = [
  {
    code: 0x0001, name: "X.509 (individual)", label: "X.509",
    description: "Individual X.509 certificate blob. Payload is not decoded or verified."
  },
  {
    code: 0x0002, name: "PKCS#7 SignedData (Authenticode)", label: "PKCS#7",
    description: "Authenticode SignedData / CMS signature."
  },
  {
    code: 0x0004, name: "TS stack signing", label: "TS stack",
    description: "Terminal Services stack signing certificate. Payload is not decoded or verified."
  },
  // Microsoft Learn documents PKCS1_SIGN=9; the checked WinTrust.h does not define this name.
  // https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-win_certificate
  {
    code: 0x0009, name: "PKCS1_SIGN", label: "PKCS1_SIGN",
    description: "WIN_CERT_TYPE_PKCS1_SIGN, documented by Microsoft Learn. " +
      "Payload is not decoded or verified."
  },
  // UEFI 2.10 section 32.2.4 defines EFI_PKCS115=0x0ef0 and EFI_GUID=0x0ef1.
  // https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html#win-certificate
  {
    code: 0x0ef0, name: "EFI PKCS#1 v1.5", label: "EFI PKCS#1 v1.5",
    description: "UEFI RSASSA-PKCS1-v1_5 signature. Payload is not decoded or verified."
  },
  {
    code: 0x0ef1, name: "EFI GUID", label: "EFI GUID",
    description: "UEFI certificate with a GUID-defined payload format. " +
      "Payload is not decoded or verified."
  }
];

const WIN_CERT_TYPE_RESERVED_1 = 0x0003; // Microsoft PE format: WIN_CERTIFICATE type 0x0003 is reserved.

const REVISION_NAMES: Record<number, string> = {
  0x0100: "Revision 1.0",
  0x0200: "Revision 2.0"
};

const describeType = (type: number): string =>
  WIN_CERTIFICATE_TYPES.find(entry => entry.code === type)?.name ??
    `Type 0x${type.toString(16).padStart(4, "0")}`;

const describeRevision = (rev: number): string =>
  REVISION_NAMES[rev] || `Revision 0x${rev.toString(16).padStart(4, "0")}`;

export interface AuthenticodeSignerInfo {
  issuer?: string;
  serialNumber?: string;
  subjectKeyIdentifier?: string;
  digestAlgorithm?: string;
  digestAlgorithmName?: string;
  signatureAlgorithm?: string;
  signatureAlgorithmName?: string;
  signingTime?: string;
}

export interface X509CertificateInfo {
  subject?: string;
  issuer?: string;
  serialNumber?: string;
  notBefore?: string;
  notAfter?: string;
  derBase64?: string;
}

export interface AuthenticodeCounterSignatureInfo {
  index: number;
  signerCertificateIndex?: number;
  certificatePathIndexes?: number[];
  signatureVerified?: boolean;
  messageDigestVerified?: boolean;
  signingTime?: string;
  message?: string;
}

export interface AuthenticodeTimestampTokenInfo {
  index: number;
  signerCertificateIndex?: number;
  certificatePathIndexes?: number[];
  certificates?: X509CertificateInfo[];
  trustPolicy?: AuthenticodeTrustPolicyInfo;
  signatureVerified?: boolean;
  messageDigestVerified?: boolean;
  signingTime?: string;
  message?: string;
}

export interface AuthenticodeSignerVerificationInfo {
  index: number;
  code?: number;
  message?: string;
  signatureVerified?: boolean;
  signerCertificateVerified?: boolean;
  signerCertificateIndex?: number;
  signingTime?: string;
  certificatePathIndexes?: number[];
  countersignatures?: AuthenticodeCounterSignatureInfo[];
  timestampTokens?: AuthenticodeTimestampTokenInfo[];
}

export type AuthenticodeCheckStatus = "pass" | "fail" | "unknown";

export interface AuthenticodeVerificationCheck {
  id: string;
  status: AuthenticodeCheckStatus;
  title: string;
  detail?: string;
}

export interface AuthenticodeTrustGap {
  id: string;
  title: string;
  detail: string;
}

export type AuthenticodeCertificateTrustStatus = "trusted" | "revoked" | "unknown";

export interface AuthenticodeCertificateTrustInfo {
  certificateIndex: number;
  status: AuthenticodeCertificateTrustStatus;
  sha1Thumbprint?: string;
  derBase64?: string;
  anchorSha1Thumbprint?: string;
  anchorSubject?: string;
  anchorDerBase64?: string;
  stores?: string[];
}

export interface AuthenticodeTrustPolicyInfo {
  generatedAt: string;
  source?: string;
  certificates: AuthenticodeCertificateTrustInfo[];
  warnings?: string[];
}

export interface AuthenticodeVerificationInfo {
  computedFileDigest?: string;
  fileDigestMatches?: boolean;
  signerVerifications?: AuthenticodeSignerVerificationInfo[];
  checks?: AuthenticodeVerificationCheck[];
  trustPolicy?: AuthenticodeTrustPolicyInfo;
  trustGaps?: AuthenticodeTrustGap[];
  warnings?: string[];
}

export interface AuthenticodeInfo {
  format: "pkcs7";
  contentType?: string;
  contentTypeName?: string;
  payloadContentType?: string;
  payloadContentTypeName?: string;
  digestAlgorithms?: string[];
  fileDigestAlgorithm?: string;
  fileDigestAlgorithmName?: string;
  fileDigest?: string;
  signers?: AuthenticodeSignerInfo[];
  certificates?: X509CertificateInfo[];
  verification?: AuthenticodeVerificationInfo;
  signerCount?: number;
  certificateCount?: number;
  warnings?: string[];
}

export interface ParsedWinCertificate {
  offset: number;
  length: number;
  availableBytes: number;
  revision: number;
  revisionName: string;
  certificateType: number;
  typeName: string;
  authenticode?: AuthenticodeInfo;
  warnings?: string[];
}

export { decodePkcs7 };

export const normalizeAuthenticodePayload = (payload: Uint8Array): Uint8Array => {
  const top = readDerElement(payload, 0);
  if (!top || top.tag !== TAG_SEQUENCE || top.end >= payload.length) {
    return payload;
  }
  for (let index = top.end; index < payload.length; index += 1) {
    if (payload[index] !== 0) {
      return payload;
    }
  }
  return payload.subarray(0, top.end);
};

export const decodeWinCertificate = (
  data: Uint8Array,
  declaredLength: number,
  offset: number
): ParsedWinCertificate => {
  const headerView = new DataView(data.buffer, data.byteOffset, Math.min(8, data.byteLength));
  const lengthField = headerView.byteLength >= 4 ? headerView.getUint32(0, true) : 0;
  const revision = headerView.byteLength >= 6 ? headerView.getUint16(4, true) : 0;
  const certificateType = headerView.byteLength >= 8 ? headerView.getUint16(6, true) : 0;
  const warnings: string[] = [];
  if (lengthField && lengthField !== declaredLength) {
    warnings.push("Length field does not match directory entry size.");
  }
  const contentStart = Math.min(8, data.byteLength);
  const payload = data.subarray(contentStart);
  if (payload.length + contentStart < declaredLength) {
    warnings.push("Certificate data is truncated.");
  }
  if (certificateType === WIN_CERT_TYPE_RESERVED_1) {
    warnings.push("WIN_CERTIFICATE type 0x0003 is reserved.");
  }
  let authenticode: AuthenticodeInfo | undefined;
  if (certificateType === 0x0002 && payload.length) {
    authenticode = decodePkcs7(normalizeAuthenticodePayload(payload));
    if (authenticode.warnings?.length) warnings.push(...authenticode.warnings);
  }
  const entry: ParsedWinCertificate = {
    offset,
    length: declaredLength,
    availableBytes: data.byteLength,
    revision,
    revisionName: describeRevision(revision),
    certificateType,
    typeName: describeType(certificateType),
    ...(authenticode ? { authenticode } : {})
  };
  if (warnings.length) entry.warnings = warnings;
  return entry;
};
