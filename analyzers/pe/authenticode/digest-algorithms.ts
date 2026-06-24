"use strict";

import { md5 } from "@noble/hashes/legacy.js";
import { sha224, sha512_224, sha512_256 } from "@noble/hashes/sha2.js";

export type AuthenticodeDigestAlgorithm =
  "MD5" | "SHA-1" | "SHA-224" | "SHA-256" | "SHA-384" | "SHA-512" |
  "SHA-512/224" | "SHA-512/256";

type LocalDigestFunction = (message: Uint8Array) => Uint8Array;

// Browser AlgorithmIdentifier names plus punctuation-insensitive aliases for the
// digest OIDs below. The OID set follows RFC 8017 Appendix B.1 HashAlgorithm;
// MD2 is intentionally absent because no local implementation is already present.
const DIGEST_ALGORITHMS_BY_NAME: Readonly<Record<string, AuthenticodeDigestAlgorithm>> = {
  md5: "MD5",
  sha1: "SHA-1",
  sha224: "SHA-224",
  sha256: "SHA-256",
  sha384: "SHA-384",
  sha512: "SHA-512",
  sha512224: "SHA-512/224",
  sha512256: "SHA-512/256"
};

// RFC 8017 Appendix B.1 defines these hash object identifiers. RFC 5754 covers
// the SHA-224/256/384/512 CMS conventions; SHA-512/224 and SHA-512/256 are the
// adjacent SHA-2 hash OIDs PKI.js/Web Crypto can also lack in legacy signatures.
export const DIGEST_ALGORITHMS_BY_OID: Readonly<Record<string, AuthenticodeDigestAlgorithm>> = {
  "1.2.840.113549.2.5": "MD5",
  "1.3.14.3.2.26": "SHA-1",
  "2.16.840.1.101.3.4.2.4": "SHA-224",
  "2.16.840.1.101.3.4.2.1": "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384",
  "2.16.840.1.101.3.4.2.3": "SHA-512",
  "2.16.840.1.101.3.4.2.5": "SHA-512/224",
  "2.16.840.1.101.3.4.2.6": "SHA-512/256"
};

// Keep Web Crypto as the default for common browser hashes. Use the existing
// local hash dependency only where Web Crypto/PKI.js commonly has no algorithm.
const LOCAL_DIGESTS: Partial<Record<AuthenticodeDigestAlgorithm, LocalDigestFunction>> = {
  MD5: md5,
  "SHA-224": sha224,
  "SHA-512/224": sha512_224,
  "SHA-512/256": sha512_256
};

const normalizeDigestName = (name: string): string => name.toLowerCase().replace(/[^a-z0-9]/g, "");

const copyToArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out.buffer;
};

const readAlgorithmName = (algorithm: AlgorithmIdentifier): string | undefined =>
  typeof algorithm === "string" ? algorithm : algorithm.name;

export const resolveDigestAlgorithmByName = (
  name: string | undefined
): AuthenticodeDigestAlgorithm | undefined =>
  name ? DIGEST_ALGORITHMS_BY_NAME[normalizeDigestName(name)] : undefined;

export const resolveDigestAlgorithmByOid = (
  oid: string | undefined
): AuthenticodeDigestAlgorithm | undefined => oid ? DIGEST_ALGORITHMS_BY_OID[oid] : undefined;

export const resolveDigestAlgorithmIdentifier = (
  algorithm: AlgorithmIdentifier
): AuthenticodeDigestAlgorithm | undefined => resolveDigestAlgorithmByName(readAlgorithmName(algorithm));

export const computeDigest = async (
  algorithm: AlgorithmIdentifier,
  data: ArrayBuffer
): Promise<ArrayBuffer> => {
  const digestAlgorithm = resolveDigestAlgorithmIdentifier(algorithm);
  const localDigest = digestAlgorithm ? LOCAL_DIGESTS[digestAlgorithm] : undefined;
  return localDigest
    ? copyToArrayBuffer(localDigest(new Uint8Array(data)))
    : crypto.subtle.digest(digestAlgorithm ?? algorithm, data);
};

export const computeDigestBytes = async (
  algorithm: AuthenticodeDigestAlgorithm,
  data: Uint8Array
): Promise<Uint8Array> => new Uint8Array(await computeDigest(algorithm, copyToArrayBuffer(data)));
