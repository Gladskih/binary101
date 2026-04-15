"use strict";

import type { AuthenticodeCheckStatus, AuthenticodeVerificationCheck } from "./index.js";
import type { Certificate, SignerInfo } from "./pkijs-runtime.js";
import { IssuerAndSerialNumber, Time, getCrypto } from "./pkijs-runtime.js";

export const CMS_MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";
export const CMS_SIGNING_TIME_OID = "1.2.840.113549.1.9.5";
export const CMS_COUNTERSIGNATURE_OID = "1.2.840.113549.1.9.6";
export const CODE_SIGNING_EKU_OID = "1.3.6.1.5.5.7.3.3";
export const TIME_STAMPING_EKU_OID = "1.3.6.1.5.5.7.3.8";
export const RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";

export const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out.buffer;
};

export const describeError = (error: unknown): string => {
  if (error instanceof Error && error.message) return error.message;
  return String(error);
};

export const getByteView = (value: unknown): Uint8Array | undefined => {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (!value || typeof value !== "object") return undefined;
  const valueBlock = (value as { valueBlock?: { valueHexView?: Uint8Array; valueHex?: ArrayBuffer } })
    .valueBlock;
  if (valueBlock?.valueHexView instanceof Uint8Array) return valueBlock.valueHexView;
  if (valueBlock?.valueHex instanceof ArrayBuffer) return new Uint8Array(valueBlock.valueHex);
  return undefined;
};

export const equalBytes = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
};

export const mergeWarnings = (warnings: string[]): string[] | undefined => {
  const merged = [...new Set(warnings)];
  return merged.length ? merged : undefined;
};

export const addCheck = (
  checks: AuthenticodeVerificationCheck[],
  id: string,
  status: AuthenticodeCheckStatus,
  title: string,
  detail?: string
): void => {
  checks.push(detail ? { id, status, title, detail } : { id, status, title });
};

export const getAttributeValue = (signer: SignerInfo, oid: string): unknown | undefined =>
  signer.signedAttrs?.attributes.find(attribute => attribute.type === oid)?.values[0];

export const getSigningTime = (signer: SignerInfo): string | undefined => {
  const value = getAttributeValue(signer, CMS_SIGNING_TIME_OID);
  if (!value) return undefined;
  try {
    return new Time({ schema: value }).value.toISOString();
  } catch {
    return undefined;
  }
};

export const parseIsoDate = (value: string | undefined): Date | undefined => {
  if (!value) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
};

export const resolveDigestAlgorithm = (oid: string): string | undefined => {
  const algorithm = getCrypto(true)?.getAlgorithmByOID(oid, true, "digestAlgorithm") as
    | { name?: string; hash?: { name?: string } }
    | undefined;
  return algorithm?.name || algorithm?.hash?.name;
};

export const matchSignerCertificate = async (
  signer: SignerInfo,
  certificates: Certificate[]
): Promise<number | undefined> => {
  if (signer.sid instanceof IssuerAndSerialNumber) {
    return certificates.findIndex(
      certificate =>
        signer.sid instanceof IssuerAndSerialNumber &&
        signer.sid.issuer.isEqual(certificate.issuer) &&
        signer.sid.serialNumber.isEqual(certificate.serialNumber)
    );
  }
  const keyIdentifier = getByteView(signer.sid);
  if (!keyIdentifier?.length) return undefined;
  for (let index = 0; index < certificates.length; index += 1) {
    const certificate = certificates[index];
    if (!certificate) continue;
    try {
      const keyHash = new Uint8Array(await certificate.getKeyHash("SHA-1"));
      if (equalBytes(keyIdentifier, keyHash)) return index;
    } catch {
      // Ignore hash lookup failures and continue with the remaining certificates.
    }
  }
  return undefined;
};
