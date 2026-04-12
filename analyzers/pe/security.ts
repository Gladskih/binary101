"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import {
  decodeWinCertificate,
  type AuthenticodeVerificationInfo,
  type ParsedWinCertificate
} from "./authenticode.js";
import type { PeDataDirectory } from "./types.js";

export interface ParsedSecurityDirectory {
  count: number;
  certs: ParsedWinCertificate[];
  warnings?: string[];
}

const WIN_CERTIFICATE_HEADER_SIZE = 8;

export type PeAuthenticodeVerifier = (
  payload: Uint8Array,
  certificate: ParsedWinCertificate
) => Promise<AuthenticodeVerificationInfo | undefined>;

const hasVerificationData = (
  verification: AuthenticodeVerificationInfo | undefined
): verification is AuthenticodeVerificationInfo =>
  !!verification &&
  (verification.computedFileDigest !== undefined ||
    verification.fileDigestMatches !== undefined ||
    !!verification.signerVerifications?.length ||
    !!verification.warnings?.length);

const attachVerification = (
  certificate: ParsedWinCertificate,
  verification: AuthenticodeVerificationInfo
): ParsedWinCertificate =>
  certificate.authenticode
    ? {
        ...certificate,
        authenticode: { ...certificate.authenticode, verification }
      }
    : certificate;

const attachVerificationWarning = (
  certificate: ParsedWinCertificate,
  message: string
): ParsedWinCertificate => {
  if (!certificate.authenticode) return certificate;
  const warnings = [...new Set([...(certificate.authenticode.verification?.warnings ?? []), message])];
  return {
    ...certificate,
    authenticode: {
      ...certificate.authenticode,
      verification: {
        ...(certificate.authenticode.verification ?? {}),
        warnings
      }
    }
  };
};

export async function parseSecurityDirectory(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  verifyAuthenticode?: PeAuthenticodeVerifier
): Promise<ParsedSecurityDirectory | null> {
  const dir = dataDirs.find(d => d.name === "SECURITY");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  const warnings: string[] = [];
  if (!dir.rva) {
    warnings.push("Attribute certificate table has a non-zero size but file offset is 0.");
    return { count: 0, certs: [], warnings };
  }
  const off = dir.rva;
  if (off >= reader.size) {
    warnings.push("Attribute certificate table starts past end of file.");
    return { count: 0, certs: [], warnings };
  }
  if ((off & 7) !== 0) {
    warnings.push("Attribute certificate table offset is not quadword aligned.");
  }
  const end = Math.min(reader.size, off + dir.size);
  const availableSize = Math.max(0, end - off);
  if (availableSize < dir.size) {
    warnings.push("Attribute certificate table is truncated by end of file.");
  }
  if (availableSize < 8) {
    warnings.push("Attribute certificate table is too small for a WIN_CERTIFICATE header.");
    return { count: 0, certs: [], warnings };
  }
  let pos = off;
  const certs: ParsedWinCertificate[] = [];
  while (pos + WIN_CERTIFICATE_HEADER_SIZE <= end) {
    const head = await reader.read(pos, WIN_CERTIFICATE_HEADER_SIZE);
    const Length = head.getUint32(0, true);
    if (Length < 8) {
      warnings.push("WIN_CERTIFICATE length is smaller than the 8-byte header.");
      break;
    }
    if ((Length & 7) !== 0) {
      warnings.push("WIN_CERTIFICATE length is not quadword aligned.");
    }
    const available = Math.min(Length, end - pos);
    const blob = await reader.readBytes(pos, available);
    let certificate = decodeWinCertificate(blob, Length, pos);
    if (verifyAuthenticode && certificate.authenticode) {
      try {
        const verification = await verifyAuthenticode(
          blob.subarray(Math.min(WIN_CERTIFICATE_HEADER_SIZE, blob.length)),
          certificate
        );
        if (hasVerificationData(verification)) {
          certificate = attachVerification(certificate, verification);
        }
      } catch (error) {
        certificate = attachVerificationWarning(
          certificate,
          `Authenticode verification failed: ${String(error)}`
        );
      }
    }
    certs.push(certificate);
    const roundedLength = Math.ceil(Length / 8) * 8;
    if (pos + roundedLength > end) {
      warnings.push("WIN_CERTIFICATE data is truncated before the rounded entry length ends.");
      pos = end;
      break;
    }
    pos += roundedLength;
  }
  if (pos !== end) {
    warnings.push("Attribute certificate table appears corrupt; rounded certificate lengths do not match the declared size.");
  }
  return warnings.length ? { count: certs.length, certs, warnings } : { count: certs.length, certs };
}
