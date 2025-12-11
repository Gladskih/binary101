"use strict";

import { decodePkcs7 } from "./pkcs7.js";

const CERT_TYPE_NAMES: Record<number, string> = {
  0x0001: "X.509 (individual)",
  0x0002: "PKCS#7 SignedData (Authenticode)",
  0x0009: "TS stack signing",
  0x000a: "PKCS#7 catalog (driver)",
  0x0ef0: "EFI PKCS1.5",
  0x0ef1: "EFI GUID",
  0x0ef2: "EFI signed data"
};

const REVISION_NAMES: Record<number, string> = {
  0x0100: "Revision 1.0",
  0x0200: "Revision 2.0"
};

const describeType = (type: number): string =>
  CERT_TYPE_NAMES[type] || `Type 0x${type.toString(16).padStart(4, "0")}`;

const describeRevision = (rev: number): string =>
  REVISION_NAMES[rev] || `Revision 0x${rev.toString(16).padStart(4, "0")}`;

export interface AuthenticodeSignerInfo {
  issuer?: string;
  serialNumber?: string;
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
  let authenticode: AuthenticodeInfo | undefined;
  if (certificateType === 0x0002 && payload.length) {
    authenticode = decodePkcs7(payload);
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

