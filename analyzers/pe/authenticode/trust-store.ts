"use strict";

import rawSnapshot from "./windows-trust-store.generated.json" with { type: "json" };

export interface AuthenticodeTrustStoreCertificate {
  thumbprint: string;
  subject?: string;
  issuer?: string;
  serialNumber?: string;
  notBefore?: string;
  notAfter?: string;
  stores?: string[];
}

export interface AuthenticodeTrustStoreSnapshot {
  schemaVersion: 1;
  generatedAt?: string;
  source?: string;
  trustedCAs: AuthenticodeTrustStoreCertificate[];
  revokedCAs: AuthenticodeTrustStoreCertificate[];
  warnings?: string[];
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object";

const optionalText = (value: unknown): string | undefined =>
  typeof value === "string" && value.length ? value : undefined;

export const normalizeThumbprint = (value: string | undefined): string | undefined => {
  const normalized = value?.replace(/[^0-9a-f]/gi, "").toUpperCase();
  return normalized?.length ? normalized : undefined;
};

const optionalTextArray = (value: unknown): string[] | undefined => {
  if (!Array.isArray(value)) return undefined;
  const strings = value.filter((item): item is string => typeof item === "string" && item.length > 0);
  return strings.length ? [...new Set(strings)].sort() : undefined;
};

const normalizeCertificate = (
  value: unknown,
  warnings: string[],
  label: string
): AuthenticodeTrustStoreCertificate | null => {
  if (!isRecord(value)) {
    warnings.push(`${label} entry is not an object.`);
    return null;
  }
  const thumbprint = normalizeThumbprint(optionalText(value["thumbprint"]));
  if (!thumbprint) {
    warnings.push(`${label} entry has no valid SHA-1 thumbprint.`);
    return null;
  }
  const subject = optionalText(value["subject"]);
  const issuer = optionalText(value["issuer"]);
  const serialNumber = optionalText(value["serialNumber"]);
  const notBefore = optionalText(value["notBefore"]);
  const notAfter = optionalText(value["notAfter"]);
  const stores = optionalTextArray(value["stores"]);
  return {
    thumbprint,
    ...(subject ? { subject } : {}),
    ...(issuer ? { issuer } : {}),
    ...(serialNumber ? { serialNumber } : {}),
    ...(notBefore ? { notBefore } : {}),
    ...(notAfter ? { notAfter } : {}),
    ...(stores ? { stores } : {})
  };
};

const normalizeCertificateArray = (
  value: unknown,
  warnings: string[],
  label: string
): AuthenticodeTrustStoreCertificate[] => {
  if (!Array.isArray(value)) {
    warnings.push(`${label} is not an array.`);
    return [];
  }
  return value
    .map((item, index) => normalizeCertificate(item, warnings, `${label}[${index}]`))
    .filter((item): item is AuthenticodeTrustStoreCertificate => item != null);
};

export const normalizeAuthenticodeTrustStore = (
  value: unknown
): AuthenticodeTrustStoreSnapshot => {
  const warnings: string[] = [];
  if (!isRecord(value)) {
    return {
      schemaVersion: 1,
      trustedCAs: [],
      revokedCAs: [],
      warnings: ["Windows Authenticode trust snapshot is not an object."]
    };
  }
  if (value["schemaVersion"] !== 1) {
    warnings.push("Windows Authenticode trust snapshot schemaVersion is not 1.");
  }
  const generatedAt = optionalText(value["generatedAt"]);
  const source = optionalText(value["source"]);
  const snapshot: AuthenticodeTrustStoreSnapshot = {
    schemaVersion: 1,
    ...(generatedAt ? { generatedAt } : {}),
    ...(source ? { source } : {}),
    trustedCAs: normalizeCertificateArray(value["trustedCAs"], warnings, "trustedCAs"),
    revokedCAs: normalizeCertificateArray(value["revokedCAs"], warnings, "revokedCAs")
  };
  const sourceWarnings = optionalTextArray(value["warnings"]);
  const mergedWarnings = [...new Set([...(sourceWarnings ?? []), ...warnings])];
  return mergedWarnings.length ? { ...snapshot, warnings: mergedWarnings } : snapshot;
};

export const hasAuthenticodeTrustStoreData = (
  snapshot: AuthenticodeTrustStoreSnapshot
): boolean =>
  !!snapshot.generatedAt && (snapshot.trustedCAs.length > 0 || snapshot.revokedCAs.length > 0);

export const authenticodeTrustStoreSnapshot = normalizeAuthenticodeTrustStore(rawSnapshot);
