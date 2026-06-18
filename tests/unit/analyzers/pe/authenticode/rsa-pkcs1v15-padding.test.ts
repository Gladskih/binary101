"use strict";

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { verifyRsaPkcs1v15Signature } from "../../../../../analyzers/pe/authenticode/rsa-pkcs1v15.js";
import {
  MD5_DIGEST_OID,
  MD5_WITH_RSA_ENCRYPTION_OID,
  RSA_ENCRYPTION_OID,
  SHA224_DIGEST_OID,
  SHA224_WITH_RSA_ENCRYPTION_OID,
  decryptSignature,
  rawRsaSignature,
  rsaSpki,
  signatureAlgorithm,
  signWithNode
} from "../../../../fixtures/pe-authenticode-rsa-helpers.js";
import { createCertificateChain } from "../../../../fixtures/pe-authenticode-signed-cms-fixtures.js";

const concatBytes = (...chunks: Uint8Array[]): Uint8Array =>
  Uint8Array.from(chunks.flatMap(chunk => [...chunk]));

const md5DigestInfo = (data: Uint8Array): Uint8Array => {
  // RFC 8017 Appendix B.1 DigestInfo DER prefix for MD5 with NULL parameters.
  const prefix = Buffer.from("3020300c06082a864886f70d020505000410", "hex");
  return concatBytes(prefix, createHash("md5").update(data).digest());
};

const md5Digest = (data: Uint8Array): Uint8Array => createHash("md5").update(data).digest();

const sha224Digest = (data: Uint8Array): Uint8Array => createHash("sha224").update(data).digest();

const pkcs1Block = (tail: Uint8Array): Uint8Array =>
  concatBytes(Uint8Array.of(0, 1), new Uint8Array(8).fill(0xff), Uint8Array.of(0), tail);

const identityRsaSpki = (length: number) =>
  rsaSpki(Uint8Array.of(2, ...new Uint8Array(length - 1)), Uint8Array.of(1));

void test("verifyRsaPkcs1v15Signature reports DigestInfo mismatches precisely", async () => {
  const chain = await createCertificateChain();
  const data = new TextEncoder().encode("binary101 malformed pkcs1");
  const otherData = new TextEncoder().encode("binary101 different pkcs1");

  const wrongDigest = await verifyRsaPkcs1v15Signature(
    data,
    await signWithNode(chain, "RSA-MD5", otherData),
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(wrongDigest?.verified, false);
  assert.match(wrongDigest?.detail ?? "", /RSA\/MD5 PKCS#1 v1\.5 signature mismatch/i);
  assert.match(wrongDigest?.detail ?? "", /DigestInfo does not match/i);

  const wrongSha224Digest = await verifyRsaPkcs1v15Signature(
    data,
    await signWithNode(chain, "RSA-SHA224", otherData),
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(SHA224_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(wrongSha224Digest?.verified, false);
  assert.match(wrongSha224Digest?.detail ?? "", /RSA PKCS#1 v1\.5 SHA-224 signature mismatch/i);
  assert.doesNotMatch(wrongSha224Digest?.detail ?? "", /RSA\/MD5/);
});

void test("verifyRsaPkcs1v15Signature rejects malformed PKCS#1 padding", async () => {
  const chain = await createCertificateChain();
  const data = new TextEncoder().encode("binary101 malformed pkcs1");
  const validBlock = await decryptSignature(chain, await signWithNode(chain, "RSA-MD5", data));
  const badFirstHeaderByte = validBlock.slice();
  badFirstHeaderByte[0] = 1;
  const badSecondHeaderByte = validBlock.slice();
  badSecondHeaderByte[1] = 0;
  const shortPadding = validBlock.slice();
  shortPadding[5] = 0;
  const badPaddingByte = validBlock.slice();
  badPaddingByte[3] = 0xfe;
  const missingSeparator = validBlock.slice();
  missingSeparator.fill(0xff, 2);

  const badFirstHeader = await verifyRsaPkcs1v15Signature(
    data,
    await rawRsaSignature(chain, badFirstHeaderByte),
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(badFirstHeader?.verified, false);
  assert.match(badFirstHeader?.detail ?? "", /block type is not 00 01/i);

  const badSecondHeader = await verifyRsaPkcs1v15Signature(
    data,
    await rawRsaSignature(chain, badSecondHeaderByte),
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(badSecondHeader?.verified, false);
  assert.match(badSecondHeader?.detail ?? "", /block type is not 00 01/i);

  const shortPaddingResult = await verifyRsaPkcs1v15Signature(
    data,
    await rawRsaSignature(chain, shortPadding),
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(shortPaddingResult?.verified, false);
  assert.match(shortPaddingResult?.detail ?? "", /padding is shorter than eight bytes/i);

  const badPaddingByteResult = await verifyRsaPkcs1v15Signature(
    data,
    await rawRsaSignature(chain, badPaddingByte),
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(badPaddingByteResult?.verified, false);
  assert.match(badPaddingByteResult?.detail ?? "", /padding contains non-0xff bytes/i);

  const missingSeparatorResult = await verifyRsaPkcs1v15Signature(
    data,
    await rawRsaSignature(chain, missingSeparator),
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(missingSeparatorResult?.verified, false);
  assert.match(missingSeparatorResult?.detail ?? "", /padding separator is missing/i);
});

void test("verifyRsaPkcs1v15Signature enforces encoded-message length boundaries", async () => {
  const data = new TextEncoder().encode("binary101 malformed pkcs1");
  const digestInfo = md5DigestInfo(data);
  const exactMinimumBlock = pkcs1Block(digestInfo);
  const tooShortBlock = exactMinimumBlock.subarray(0, exactMinimumBlock.length - 1);
  const zeroPaddedDigestInfo = concatBytes(exactMinimumBlock, Uint8Array.of(0));

  const exactMinimum = await verifyRsaPkcs1v15Signature(
    data,
    exactMinimumBlock,
    identityRsaSpki(exactMinimumBlock.length),
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(exactMinimum?.verified, true);

  const tooShort = await verifyRsaPkcs1v15Signature(
    data,
    tooShortBlock,
    identityRsaSpki(tooShortBlock.length),
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(tooShort?.verified, false);
  assert.match(tooShort?.detail ?? "", /shorter than the RFC 8017 minimum/i);

  const zeroPaddedDigest = await verifyRsaPkcs1v15Signature(
    data,
    zeroPaddedDigestInfo,
    identityRsaSpki(zeroPaddedDigestInfo.length),
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(zeroPaddedDigest?.verified, false);
  assert.match(zeroPaddedDigest?.detail ?? "", /DigestInfo does not match/i);

  const tinyBlock = await verifyRsaPkcs1v15Signature(
    data,
    Uint8Array.of(1),
    rsaSpki(Uint8Array.of(3), Uint8Array.of(3)),
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(tinyBlock?.verified, false);
  assert.match(tinyBlock?.detail ?? "", /shorter than the RFC 8017 minimum/i);
});

void test("verifyRsaPkcs1v15Signature accepts legacy rsaEncryption raw MD5 digests only by OID pair", async () => {
  const data = new TextEncoder().encode("binary101 legacy raw md5 pkcs7");
  const rawDigestBlock = pkcs1Block(md5Digest(data));

  const legacyRawDigest = await verifyRsaPkcs1v15Signature(
    data,
    rawDigestBlock,
    identityRsaSpki(rawDigestBlock.length),
    signatureAlgorithm(RSA_ENCRYPTION_OID),
    MD5_DIGEST_OID
  );
  assert.strictEqual(legacyRawDigest?.verified, true);
  assert.match(legacyRawDigest?.detail ?? "", /legacy RSA\/MD5 raw digest under rsaEncryption/);

  const wrongRawDigestBlock = pkcs1Block(md5Digest(new TextEncoder().encode("different raw md5 input")));
  const wrongLegacyRawDigest = await verifyRsaPkcs1v15Signature(
    data,
    wrongRawDigestBlock,
    identityRsaSpki(wrongRawDigestBlock.length),
    signatureAlgorithm(RSA_ENCRYPTION_OID),
    MD5_DIGEST_OID
  );
  assert.strictEqual(wrongLegacyRawDigest?.verified, false);
  assert.match(wrongLegacyRawDigest?.detail ?? "", /DigestInfo or legacy raw digest does not match/);

  const md5WithRsaDigestInfoOnly = await verifyRsaPkcs1v15Signature(
    data,
    rawDigestBlock,
    identityRsaSpki(rawDigestBlock.length),
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(md5WithRsaDigestInfoOnly?.verified, false);
  assert.match(md5WithRsaDigestInfoOnly?.detail ?? "", /shorter than the RFC 8017 minimum/);

  const rawSha224DigestBlock = pkcs1Block(sha224Digest(data));
  const sha224WithRsaDigestInfoOnly = await verifyRsaPkcs1v15Signature(
    data,
    rawSha224DigestBlock,
    identityRsaSpki(rawSha224DigestBlock.length),
    signatureAlgorithm(RSA_ENCRYPTION_OID),
    SHA224_DIGEST_OID
  );
  assert.strictEqual(sha224WithRsaDigestInfoOnly?.verified, false);
  assert.match(sha224WithRsaDigestInfoOnly?.detail ?? "", /shorter than the RFC 8017 minimum/);
});
