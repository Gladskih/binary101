"use strict";

const OID_NAMES: Record<string, string> = {
  "1.2.840.113549.1.7.1": "PKCS#7 data",
  "1.2.840.113549.1.7.2": "PKCS#7 signedData",
  "1.3.6.1.4.1.311.2.1.4": "SPC_INDIRECT_DATA",
  "1.2.840.113549.2.5": "md5",
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
  "2.16.840.1.101.3.4.2.4": "sha224",
  "2.16.840.1.101.3.4.2.5": "sha512/224",
  "1.2.840.113549.1.1.1": "rsaEncryption",
  "2.5.4.3": "commonName",
  "2.5.4.6": "countryName",
  "2.5.4.7": "localityName",
  "2.5.4.8": "stateOrProvinceName",
  "2.5.4.10": "organizationName",
  "2.5.4.11": "organizationalUnitName",
  "1.2.840.113549.1.9.3": "contentType",
  "1.2.840.113549.1.9.4": "messageDigest",
  "1.2.840.113549.1.9.5": "signingTime",
  "1.2.840.113549.1.9.6": "countersignature"
};

export const describeOid = (oid?: string): string | undefined => (oid ? OID_NAMES[oid] || oid : undefined);

export const NAME_OID_KEYS: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.10": "O",
  "2.5.4.11": "OU"
};

export const SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4";
export const SIGNING_TIME_OID = "1.2.840.113549.1.9.5";

