"use strict";

import type { FileRange } from "../layout/file-ranges.js";
import { buildStrongNameHashInput } from "./strong-name-hash.js";
import type { FileRangeReader } from "../../file-range-reader.js";

type RsaPublicKey = {
  hashAlgorithm: number;
  modulus: Uint8Array;
  exponent: Uint8Array;
};

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
const base64Url = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
const reverseBytes = (bytes: Uint8Array): Uint8Array => Uint8Array.from(bytes).reverse();
const trimLeadingZeroes = (bytes: Uint8Array): Uint8Array => {
  const first = bytes.findIndex(byte => byte !== 0);
  return first === -1 ? new Uint8Array([0]) : bytes.subarray(first);
};

const isEcmaStandardPublicKey = (publicKey: number[]): boolean =>
  // ECMA-335 II.6.2.1.3 defines this 16-byte Standard Public Key for Standard Library assemblies.
  // Spec: https://www.ecma-international.org/publications-and-standards/standards/ecma-335/
  publicKey.length === 16 && publicKey.every((byte, index) => byte === (index === 8 ? 4 : 0));

const algorithmName = (hashAlgorithm: number): string | null => {
  // Assembly.HashAlgId values use ECMA-335 II.22.2 Assembly metadata plus Windows ALG_ID values:
  // https://carlwa.com/ecma-335/#ii.22.2-assembly-0x20
  if (hashAlgorithm === 0x00008004 || hashAlgorithm === 0) return "SHA-1";
  if (hashAlgorithm === 0x0000800c) return "SHA-256";
  if (hashAlgorithm === 0x0000800d) return "SHA-384";
  if (hashAlgorithm === 0x0000800e) return "SHA-512";
  return null;
};

const parseRsaPublicKey = (publicKey: number[] | undefined, issues: string[]): RsaPublicKey | null => {
  if (!publicKey?.length) {
    issues.push("Assembly public key blob is absent.");
    return null;
  }
  const bytes = new Uint8Array(publicKey);
  if (bytes.length < 32) {
    issues.push("Assembly public key blob is too short for an RSA public key.");
    return null;
  }
  return parseRsaPublicKeyFields(bytes, new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength), issues);
};

const parseRsaPublicKeyFields = (
  bytes: Uint8Array,
  view: DataView,
  issues: string[]
): RsaPublicKey | null => {
  // PublicKey blob layout follows the CLR strong-name PUBLICKEYBLOB/CryptoAPI RSA1 shape:
  // https://github.com/0xd4d/dnlib/blob/master/src/DotNet/StrongNameKey.cs
  if (view.getUint32(0, true) !== 0x00002400 || view.getUint8(12) !== 6) {
    issues.push("Assembly public key blob is not an RSA strong-name public key.");
    return null;
  }
  if (view.getUint8(13) !== 2 || view.getUint32(16, true) !== 0x00002400) {
    issues.push("Assembly public key blob has an unsupported RSA header.");
    return null;
  }
  if (view.getUint32(20, true) !== 0x31415352) {
    issues.push("Assembly public key blob is not an RSA1 public key.");
    return null;
  }
  const modulusBytes = view.getUint32(24, true) / 8;
  if (!Number.isInteger(modulusBytes) || modulusBytes <= 0 || 32 + modulusBytes > bytes.length) {
    issues.push("Assembly public key blob has an invalid RSA modulus size.");
    return null;
  }
  return {
    hashAlgorithm: view.getUint32(4, true),
    modulus: reverseBytes(bytes.subarray(32, 32 + modulusBytes)),
    exponent: trimLeadingZeroes(reverseBytes(bytes.subarray(28, 32)))
  };
};

const validSignatureRanges = (ranges: FileRange[], size: number, fileSize: number): boolean =>
  ranges.every(range => Number.isSafeInteger(range.start) && Number.isSafeInteger(range.end) &&
    range.start >= 0 && range.end > range.start && range.end <= fileSize) &&
  ranges.reduce((sum, range) => sum + range.end - range.start, 0) === size;

const strongNameCrypto = (issues: string[]): SubtleCrypto | null => {
  const subtle = globalThis.crypto?.subtle;
  if (subtle) return subtle;
  issues.push("WebCrypto is unavailable, so strong-name verification cannot run.");
  return null;
};

const verifyRsaStrongName = async (
  subtle: SubtleCrypto, rsaPublicKey: RsaPublicKey, hashName: string,
  signature: Uint8Array, input: Uint8Array, issues: string[]
): Promise<boolean | null> => {
  try {
    const key = await subtle.importKey(
      "jwk",
      { kty: "RSA", n: base64Url(trimLeadingZeroes(rsaPublicKey.modulus)), e: base64Url(trimLeadingZeroes(rsaPublicKey.exponent)), ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: hashName },
      false,
      ["verify"]
    );
    return await subtle.verify(
      "RSASSA-PKCS1-v1_5", key, toArrayBuffer(reverseBytes(signature)), toArrayBuffer(input)
    );
  } catch {
    issues.push("RSA key import or strong-name verification failed.");
    return null;
  }
};

export const verifyStrongNameSignature = async (
  reader: FileRangeReader,
  publicKey: number[] | undefined,
  signature: Uint8Array,
  signatureRanges: FileRange[],
  hashAlgorithm: number,
  issues: string[]
): Promise<boolean | null> => {
  if (publicKey && isEcmaStandardPublicKey(publicKey)) return null;
  const rsaPublicKey = parseRsaPublicKey(publicKey, issues);
  if (!rsaPublicKey) return null;
  const hashName = algorithmName(hashAlgorithm || rsaPublicKey.hashAlgorithm);
  if (!hashName) {
    issues.push("Assembly hash algorithm is unsupported for strong-name verification.");
    return null;
  }
  const subtle = strongNameCrypto(issues);
  if (!subtle) return null;
  if (!validSignatureRanges(signatureRanges, signature.length, reader.size)) {
    issues.push("Strong-name signature file ranges are incomplete or outside the file.");
    return null;
  }
  const input = await buildStrongNameHashInput(reader, signatureRanges, issues);
  if (!input) return null;
  return verifyRsaStrongName(subtle, rsaPublicKey, hashName, signature, input, issues);
};
