"use strict";

import assert from "node:assert/strict";
import {
  constants,
  createPrivateKey,
  createPublicKey,
  privateEncrypt,
  publicDecrypt,
  sign as nodeSign
} from "node:crypto";
import {
  TAG_BIT_STRING,
  TAG_OCTET_STRING,
  TAG_SEQUENCE,
  readDerChildren,
  readDerElement
} from "../../analyzers/pe/authenticode/der.js";
import type {
  PkijsAlgorithmIdentifier,
  PkijsSubjectPublicKeyInfo
} from "../../analyzers/pe/authenticode/pkijs-runtime.js";
import type { createCertificateChain } from "./pe-authenticode-signed-cms-fixtures.js";

// RFC 8017 Appendix A.2.4/B.1: RSA PKCS #1 v1.5 signature and hash OIDs.
export const RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
export const MD5_DIGEST_OID = "1.2.840.113549.2.5";
export const SHA224_DIGEST_OID = "2.16.840.1.101.3.4.2.4";
export const MD5_WITH_RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.4";
export const SHA1_WITH_RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.5";
export const SHA224_WITH_RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.14";
export const SHA512_224_WITH_RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.15";
export const SHA512_256_WITH_RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.16";

export type CertificateChain = Awaited<ReturnType<typeof createCertificateChain>>;

const copyToArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out.buffer;
};

const privateKeyFromChain = async (chain: CertificateChain) =>
  createPrivateKey({
    key: Buffer.from(await crypto.subtle.exportKey("pkcs8", chain.rootPrivateKey)),
    format: "der",
    type: "pkcs8"
  });

const replaceFirst = (source: Uint8Array, needle: Uint8Array, replacement: Uint8Array): Uint8Array => {
  assert.strictEqual(needle.length, replacement.length);
  const out = source.slice();
  const offset = source.findIndex((_, index) =>
    index + needle.length <= source.length &&
    needle.every((byte, needleIndex) => source[index + needleIndex] === byte)
  );
  assert.notStrictEqual(offset, -1);
  out.set(replacement, offset);
  return out;
};

const oidDer = (oid: string): Uint8Array => {
  const parts = oid.split(".").map(part => Number.parseInt(part, 10));
  const first = parts[0];
  const second = parts[1];
  if (first == null || second == null) throw new Error(`OID has too few arcs: ${oid}`);
  const encoded: number[] = [first * 40 + second];
  parts.slice(2).forEach(part => {
    const stack = [part & 0x7f];
    let remaining = part >>> 7;
    while (remaining > 0) {
      stack.unshift((remaining & 0x7f) | 0x80);
      remaining >>>= 7;
    }
    encoded.push(...stack);
  });
  return Uint8Array.of(0x06, encoded.length, ...encoded);
};

const derLength = (length: number): Uint8Array => {
  if (length < 0x80) return Uint8Array.of(length);
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>>= 8;
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
};

const derElement = (tag: number, content: Uint8Array): Uint8Array =>
  Uint8Array.of(tag, ...derLength(content.length), ...content);

const derSequence = (...items: Uint8Array[]): Uint8Array =>
  derElement(0x30, Uint8Array.from(items.flatMap(item => [...item])));

const derInteger = (bytes: Uint8Array): Uint8Array => derElement(0x02, bytes);

export const signatureAlgorithm = (algorithmId: string): PkijsAlgorithmIdentifier => ({ algorithmId });

export const signWithNode = async (
  chain: CertificateChain,
  algorithm: string,
  data: Uint8Array
): Promise<Uint8Array> => new Uint8Array(nodeSign(algorithm, data, await privateKeyFromChain(chain)));

export const spkiBytes = (publicKeyInfo: PkijsSubjectPublicKeyInfo): Uint8Array =>
  new Uint8Array(publicKeyInfo.toSchema().toBER(false));

export const publicKeyInfoFromDer = (bytes: Uint8Array): PkijsSubjectPublicKeyInfo => ({
  algorithm: { algorithmId: RSA_ENCRYPTION_OID },
  importKey: async (): Promise<void> => undefined,
  toSchema: () => ({ toBER: (): ArrayBuffer => copyToArrayBuffer(bytes) })
});

export const spkiWithWrongAlgorithmOid = (source: Uint8Array): Uint8Array =>
  replaceFirst(source, oidDer(RSA_ENCRYPTION_OID), oidDer(SHA1_WITH_RSA_ENCRYPTION_OID));

export const spkiWithNonZeroUnusedBits = (source: Uint8Array): Uint8Array => {
  const top = readDerElement(source, 0);
  assert.ok(top);
  assert.strictEqual(top.tag, TAG_SEQUENCE);
  const [, bitString] = readDerChildren(source, top);
  assert.ok(bitString);
  assert.strictEqual(bitString.tag, TAG_BIT_STRING);
  const out = source.slice();
  out[bitString.start + bitString.header] = 1;
  return out;
};

const spkiChildElements = (source: Uint8Array) => {
  const top = readDerElement(source, 0);
  assert.ok(top);
  const [algorithm, bitString] = readDerChildren(source, top);
  assert.ok(algorithm);
  assert.ok(bitString);
  return { algorithm, bitString };
};

export const spkiWithTopTag = (source: Uint8Array): Uint8Array => {
  const out = source.slice();
  out[0] = TAG_OCTET_STRING;
  return out;
};

export const spkiWithAlgorithmTag = (source: Uint8Array): Uint8Array => {
  const out = source.slice();
  out[spkiChildElements(source).algorithm.start] = TAG_OCTET_STRING;
  return out;
};

export const spkiWithBitStringTag = (source: Uint8Array): Uint8Array => {
  const out = source.slice();
  out[spkiChildElements(source).bitString.start] = TAG_OCTET_STRING;
  return out;
};

export const spkiWithRsaTopTag = (source: Uint8Array): Uint8Array => {
  const { bitString } = spkiChildElements(source);
  const out = source.slice();
  out[bitString.start + bitString.header + 1] = TAG_OCTET_STRING;
  return out;
};

export const spkiWithModulusTag = (source: Uint8Array): Uint8Array => {
  const { bitString } = spkiChildElements(source);
  const rsaStart = bitString.start + bitString.header + 1;
  const rsaBytes = source.subarray(rsaStart, bitString.end);
  const rsaTop = readDerElement(rsaBytes, 0);
  assert.ok(rsaTop);
  const [modulus] = readDerChildren(rsaBytes, rsaTop);
  assert.ok(modulus);
  const out = source.slice();
  out[rsaStart + modulus.start] = TAG_OCTET_STRING;
  return out;
};

export const rsaSpki = (modulus: Uint8Array, exponent: Uint8Array): PkijsSubjectPublicKeyInfo =>
  publicKeyInfoFromDer(
    derSequence(
      derSequence(oidDer(RSA_ENCRYPTION_OID), derElement(0x05, Uint8Array.of())),
      derElement(0x03, Uint8Array.of(0, ...derSequence(derInteger(modulus), derInteger(exponent))))
    )
  );

export const rawRsaSignature = async (chain: CertificateChain, encodedMessage: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(privateEncrypt({
    key: await privateKeyFromChain(chain),
    padding: constants.RSA_NO_PADDING
  }, encodedMessage));

export const decryptSignature = async (chain: CertificateChain, signature: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(publicDecrypt({
    key: createPublicKey(await privateKeyFromChain(chain)),
    padding: constants.RSA_NO_PADDING
  }, signature));
