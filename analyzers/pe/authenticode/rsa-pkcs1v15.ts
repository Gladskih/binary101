"use strict";

import {
  computeDigestBytes,
  resolveDigestAlgorithmByOid,
  type AuthenticodeDigestAlgorithm
} from "./digest-algorithms.js";
import { equalBytes } from "./pkijs-support.js";
import {
  TAG_BIT_STRING,
  TAG_INTEGER,
  TAG_OID,
  TAG_SEQUENCE,
  decodeOid,
  readDerChildren,
  readDerElement
} from "./der.js";
import type { PkijsAlgorithmIdentifier, PkijsSubjectPublicKeyInfo } from "./pkijs-runtime.js";

export type RsaPkcs1v15VerificationResult = {
  verified?: boolean;
  detail?: string;
};

const RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";

// RFC 8017 Appendix A.2.4 defines the PKCS #1 v1.5 RSA-with-hash signature OIDs.
const RSA_SIGNATURE_DIGESTS_BY_OID: Readonly<Record<string, AuthenticodeDigestAlgorithm>> = {
  "1.2.840.113549.1.1.4": "MD5",
  "1.2.840.113549.1.1.5": "SHA-1",
  "1.2.840.113549.1.1.14": "SHA-224",
  "1.2.840.113549.1.1.11": "SHA-256",
  "1.2.840.113549.1.1.12": "SHA-384",
  "1.2.840.113549.1.1.13": "SHA-512",
  "1.2.840.113549.1.1.15": "SHA-512/224",
  "1.2.840.113549.1.1.16": "SHA-512/256"
};

type LocalRsaDigestAlgorithm = "MD5" | "SHA-224" | "SHA-512/224" | "SHA-512/256";

const LOCAL_RSA_DIGESTS = new Set<AuthenticodeDigestAlgorithm>([
  "MD5",
  "SHA-224",
  "SHA-512/224",
  "SHA-512/256"
]);

// RFC 8017 section 9.2 and Appendix B.1 define the DER DigestInfo encodings.
// Only locally verified digests are listed; Web Crypto remains responsible for
// RSA/SHA-1, RSA/SHA-256, RSA/SHA-384, and RSA/SHA-512 through PKI.js.
const DIGEST_INFO_PREFIX_BY_ALGORITHM: Readonly<Record<LocalRsaDigestAlgorithm, string>> = {
  MD5: "3020300c06082a864886f70d020505000410",
  "SHA-224": "302d300d06096086480165030402040500041c",
  "SHA-512/224": "302d300d06096086480165030402050500041c",
  "SHA-512/256": "3031300d060960864801650304020605000420"
};

type RsaPublicKey = {
  modulus: bigint;
  exponent: bigint;
  byteLength: number;
};

type EncodedMessageForm = "digestInfo" | "legacyRawDigest";

type ExpectedEncodedTail = {
  form: EncodedMessageForm;
  bytes: Uint8Array;
};

type EncodedMessageResult =
  | { verified: true; form: EncodedMessageForm }
  | { verified: false; failure: string };

const bytesToBigInt = (bytes: Uint8Array): bigint => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};

const bigIntToFixedBytes = (value: bigint, length: number): Uint8Array => {
  const out = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
};

const modPow = (base: bigint, exponent: bigint, modulus: bigint): bigint => {
  let result = 1n;
  let power = base % modulus;
  let remainingExponent = exponent;
  while (remainingExponent > 0n) {
    if ((remainingExponent & 1n) === 1n) result = (result * power) % modulus;
    power = (power * power) % modulus;
    remainingExponent >>= 1n;
  }
  return result;
};

const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from(
    Array.from({ length: Math.floor(hex.length / 2) }, (_, index) =>
      Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
    )
  );

const concatBytes = (left: Uint8Array, right: Uint8Array): Uint8Array => {
  const out = new Uint8Array(left.length + right.length);
  out.set(left);
  out.set(right, left.length);
  return out;
};

const readPositiveIntegerBytes = (bytes: Uint8Array, offset: number): Uint8Array | undefined => {
  const element = readDerElement(bytes, offset);
  if (!element || element.tag !== TAG_INTEGER) return undefined;
  const raw = bytes.subarray(element.start + element.header, element.end);
  if ((raw[0] ?? 0) >= 0x80) return undefined;
  const firstValueByte = raw.findIndex(byte => byte !== 0);
  return firstValueByte < 0 ? new Uint8Array() : raw.subarray(firstValueByte);
};

const readSpkiDerBytes = (publicKeyInfo: PkijsSubjectPublicKeyInfo): Uint8Array | undefined => {
  const encoded = publicKeyInfo.toSchema().toBER(false);
  return encoded instanceof ArrayBuffer ? new Uint8Array(encoded) : undefined;
};

const parseRsaPublicKey = (publicKeyInfo: PkijsSubjectPublicKeyInfo): RsaPublicKey | undefined => {
  const bytes = readSpkiDerBytes(publicKeyInfo);
  const top = bytes ? readDerElement(bytes, 0) : null;
  if (!bytes || !top || top.tag !== TAG_SEQUENCE) return undefined;
  const [algorithm, bitString] = readDerChildren(bytes, top);
  if (!algorithm || !bitString || algorithm.tag !== TAG_SEQUENCE || bitString.tag !== TAG_BIT_STRING) return undefined;
  const oid = readDerElement(bytes, algorithm.start + algorithm.header);
  const algorithmOid = oid?.tag === TAG_OID ? decodeOid(bytes, oid.start + oid.header, oid.length) : undefined;
  if (algorithmOid !== RSA_ENCRYPTION_OID) return undefined;
  const unusedBitsOffset = bitString.start + bitString.header;
  if (bytes[unusedBitsOffset] !== 0) return undefined;
  const rsaBytes = bytes.subarray(unusedBitsOffset + 1, bitString.end);
  const rsaTop = readDerElement(rsaBytes, 0);
  if (!rsaTop || rsaTop.tag !== TAG_SEQUENCE) return undefined;
  const [modulusElement, exponentElement] = readDerChildren(rsaBytes, rsaTop);
  const modulus = modulusElement
    ? readPositiveIntegerBytes(rsaBytes, modulusElement.start)
    : undefined;
  const exponent = exponentElement
    ? readPositiveIntegerBytes(rsaBytes, exponentElement.start)
    : undefined;
  if (!modulus?.length || !exponent?.length) return undefined;
  const modulusValue = bytesToBigInt(modulus);
  const exponentValue = bytesToBigInt(exponent);
  return {
    modulus: modulusValue,
    exponent: exponentValue,
    byteLength: modulus.length
  };
};

const buildExpectedEncodedTails = async (
  algorithm: LocalRsaDigestAlgorithm,
  data: Uint8Array,
  signatureAlgorithm: PkijsAlgorithmIdentifier
): Promise<ExpectedEncodedTail[]> => {
  // RFC 8017 section 9.2 and Appendix B.1: EMSA-PKCS1-v1_5 signs a DER
  // DigestInfo whose AlgorithmIdentifier parameters are NULL for these hashes.
  const prefix = hexToBytes(DIGEST_INFO_PREFIX_BY_ALGORITHM[algorithm]);
  const digest = await computeDigestBytes(algorithm, data);
  const tails: ExpectedEncodedTail[] = [
    { form: "digestInfo", bytes: concatBytes(prefix, digest) }
  ];
  if (algorithm === "MD5" && signatureAlgorithm.algorithmId === RSA_ENCRYPTION_OID) {
    // RFC 2313 section 1 describes the PKCS #7 RSA signature use case as
    // encrypting an octet string containing the message digest. Legacy
    // Authenticode timestamps verified by Windows signtool use that raw MD5
    // form with rsaEncryption plus an external digestAlgorithm.
    tails.push({ form: "legacyRawDigest", bytes: digest });
  }
  return tails;
};

const verifyEncodedMessageTail = (
  encodedMessage: Uint8Array,
  expectedTails: ExpectedEncodedTail[]
): EncodedMessageResult => {
  // RFC 8017 section 9.2: EM = 00 || 01 || PS || 00 || T, with at least
  // eight 0xff bytes in PS; that makes T.length + 11 the minimum length.
  const minimumTailLength = Math.min(...expectedTails.map(tail => tail.bytes.length));
  if (encodedMessage.length < minimumTailLength + 11) {
    return { verified: false, failure: "Encoded message is shorter than the RFC 8017 minimum." };
  }
  if (encodedMessage[0] !== 0 || encodedMessage[1] !== 1) {
    return { verified: false, failure: "Encoded message block type is not 00 01." };
  }
  const separator = encodedMessage.indexOf(0, 2);
  if (separator === -1) {
    return { verified: false, failure: "Encoded message padding separator is missing." };
  }
  if (separator < 10) {
    return { verified: false, failure: "Encoded message padding is shorter than eight bytes." };
  }
  if (!encodedMessage.subarray(2, separator).every(byte => byte === 0xff)) {
    return { verified: false, failure: "Encoded message padding contains non-0xff bytes." };
  }
  const tail = encodedMessage.subarray(separator + 1);
  const match = expectedTails.find(expectedTail => equalBytes(tail, expectedTail.bytes));
  if (!match) {
    const rawDigestAllowed = expectedTails.some(expectedTail => expectedTail.form === "legacyRawDigest");
    return {
      verified: false,
      failure: rawDigestAllowed
        ? "DigestInfo or legacy raw digest does not match."
        : "DigestInfo does not match."
    };
  }
  return { verified: true, form: match.form };
};

const resolveRsaDigestAlgorithm = (
  signatureAlgorithm: PkijsAlgorithmIdentifier,
  digestAlgorithmOid: string | undefined
): AuthenticodeDigestAlgorithm | undefined => {
  if (signatureAlgorithm.algorithmId === RSA_ENCRYPTION_OID) {
    return resolveDigestAlgorithmByOid(digestAlgorithmOid);
  }
  return RSA_SIGNATURE_DIGESTS_BY_OID[signatureAlgorithm.algorithmId];
};

const isLocalRsaDigestAlgorithm = (
  algorithm: AuthenticodeDigestAlgorithm | undefined
): algorithm is LocalRsaDigestAlgorithm => !!algorithm && LOCAL_RSA_DIGESTS.has(algorithm);

const createDetail = (
  algorithm: AuthenticodeDigestAlgorithm,
  result: EncodedMessageResult
): string => {
  if (result.verified && result.form === "legacyRawDigest") {
    return "Verified locally with legacy RSA/MD5 raw digest under rsaEncryption.";
  }
  if (result.verified && algorithm === "MD5") {
    return "Verified locally with legacy RSA/MD5; RFC 8017 keeps MD5 only for compatibility.";
  }
  if (result.verified) return `Verified locally with RSA PKCS#1 v1.5 ${algorithm}.`;
  const suffix = ` ${result.failure}`;
  return algorithm === "MD5"
    ? `RSA/MD5 PKCS#1 v1.5 signature mismatch.${suffix}`
    : `RSA PKCS#1 v1.5 ${algorithm} signature mismatch.${suffix}`;
};

export const shouldVerifyRsaPkcs1v15Locally = (
  signatureAlgorithm: PkijsAlgorithmIdentifier,
  digestAlgorithmOid?: string
): boolean => {
  const algorithm = resolveRsaDigestAlgorithm(signatureAlgorithm, digestAlgorithmOid);
  return isLocalRsaDigestAlgorithm(algorithm);
};

export const verifyRsaPkcs1v15Signature = async (
  data: Uint8Array,
  signature: Uint8Array,
  publicKeyInfo: PkijsSubjectPublicKeyInfo,
  signatureAlgorithm: PkijsAlgorithmIdentifier,
  digestAlgorithmOid?: string
): Promise<RsaPkcs1v15VerificationResult | undefined> => {
  const algorithm = resolveRsaDigestAlgorithm(signatureAlgorithm, digestAlgorithmOid);
  if (!isLocalRsaDigestAlgorithm(algorithm)) return undefined;
  const publicKey = parseRsaPublicKey(publicKeyInfo);
  if (!publicKey) return { detail: "Unable to parse RSA SubjectPublicKeyInfo." };
  if (signature.length !== publicKey.byteLength) {
    return { verified: false, detail: "RSA signature length does not match the modulus length." };
  }
  if (bytesToBigInt(signature) >= publicKey.modulus) {
    return { verified: false, detail: "RSA signature representative is outside the modulus range." };
  }
  const encodedValue = bigIntToFixedBytes(
    modPow(bytesToBigInt(signature), publicKey.exponent, publicKey.modulus),
    publicKey.byteLength
  );
  const encodedMessageResult = verifyEncodedMessageTail(
    encodedValue,
    await buildExpectedEncodedTails(algorithm, data, signatureAlgorithm)
  );
  return {
    verified: encodedMessageResult.verified,
    detail: createDetail(algorithm, encodedMessageResult)
  };
};
