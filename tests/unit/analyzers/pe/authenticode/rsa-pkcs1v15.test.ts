"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  shouldVerifyRsaPkcs1v15Locally,
  verifyRsaPkcs1v15Signature
} from "../../../../../analyzers/pe/authenticode/rsa-pkcs1v15.js";
import {
  MD5_DIGEST_OID,
  MD5_WITH_RSA_ENCRYPTION_OID,
  RSA_ENCRYPTION_OID,
  SHA1_WITH_RSA_ENCRYPTION_OID,
  SHA224_WITH_RSA_ENCRYPTION_OID,
  SHA512_224_WITH_RSA_ENCRYPTION_OID,
  SHA512_256_WITH_RSA_ENCRYPTION_OID,
  publicKeyInfoFromDer,
  rsaSpki,
  signatureAlgorithm,
  signWithNode,
  spkiBytes,
  spkiWithAlgorithmTag,
  spkiWithBitStringTag,
  spkiWithModulusTag,
  spkiWithNonZeroUnusedBits,
  spkiWithRsaTopTag,
  spkiWithTopTag,
  spkiWithWrongAlgorithmOid,
  type CertificateChain
} from "../../../../fixtures/pe-authenticode-rsa-helpers.js";
import { createCertificateChain } from "../../../../fixtures/pe-authenticode-signed-cms-fixtures.js";

const assertLocalSignaturePasses = async (
  chain: CertificateChain,
  data: Uint8Array,
  nodeAlgorithm: string,
  oid: string,
  expectedDetail: RegExp
): Promise<void> => {
  const result = await verifyRsaPkcs1v15Signature(
    data,
    await signWithNode(chain, nodeAlgorithm, data),
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(oid)
  );
  assert.strictEqual(result?.verified, true, oid);
  assert.match(result?.detail ?? "", expectedDetail, oid);
};

const assertMalformedSpki = async (
  data: Uint8Array,
  signature: Uint8Array,
  spki: Uint8Array
): Promise<void> => {
  const result = await verifyRsaPkcs1v15Signature(
    data,
    signature,
    publicKeyInfoFromDer(spki),
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(result?.verified, undefined);
  assert.match(result?.detail ?? "", /Unable to parse RSA SubjectPublicKeyInfo/);
};

void test("shouldVerifyRsaPkcs1v15Locally selects only locally implemented RSA digests", () => {
  assert.strictEqual(shouldVerifyRsaPkcs1v15Locally(signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)), true);
  assert.strictEqual(shouldVerifyRsaPkcs1v15Locally(signatureAlgorithm(SHA1_WITH_RSA_ENCRYPTION_OID)), false);
  assert.strictEqual(shouldVerifyRsaPkcs1v15Locally(signatureAlgorithm("1.2.3.4")), false);
  assert.strictEqual(shouldVerifyRsaPkcs1v15Locally(signatureAlgorithm(RSA_ENCRYPTION_OID), MD5_DIGEST_OID), true);
});

void test("verifyRsaPkcs1v15Signature accepts each local DigestInfo prefix", async () => {
  const chain = await createCertificateChain();
  const data = new TextEncoder().encode("binary101 local rsa signatures");

  await assertLocalSignaturePasses(chain, data, "RSA-MD5", MD5_WITH_RSA_ENCRYPTION_OID, /legacy RSA\/MD5/);
  await assertLocalSignaturePasses(
    chain,
    data,
    "RSA-SHA224",
    SHA224_WITH_RSA_ENCRYPTION_OID,
    /^Verified locally with RSA PKCS#1 v1\.5 SHA-224\.$/
  );
  await assertLocalSignaturePasses(
    chain,
    data,
    "RSA-SHA512/224",
    SHA512_224_WITH_RSA_ENCRYPTION_OID,
    /^Verified locally with RSA PKCS#1 v1\.5 SHA-512\/224\.$/
  );
  await assertLocalSignaturePasses(
    chain,
    data,
    "RSA-SHA512/256",
    SHA512_256_WITH_RSA_ENCRYPTION_OID,
    /^Verified locally with RSA PKCS#1 v1\.5 SHA-512\/256\.$/
  );

  const fallbackResult = await verifyRsaPkcs1v15Signature(
    data,
    await signWithNode(chain, "RSA-MD5", data),
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(RSA_ENCRYPTION_OID),
    MD5_DIGEST_OID
  );
  assert.strictEqual(fallbackResult?.verified, true);
});

void test("verifyRsaPkcs1v15Signature reports invalid signature boundary cases", async () => {
  const chain = await createCertificateChain();
  const data = new TextEncoder().encode("binary101 invalid rsa signatures");
  const signature = await signWithNode(chain, "RSA-MD5", data);
  const mismatchedSignature = signature.slice();
  const lastIndex = mismatchedSignature.length - 1;
  const lastByte = mismatchedSignature[lastIndex];
  if (lastByte == null) throw new Error("RSA signature fixture is empty.");
  mismatchedSignature[lastIndex] = lastByte ^ 0xff;
  const outOfRangeSignature = new Uint8Array(signature.length);
  outOfRangeSignature.fill(0xff);

  const mismatch = await verifyRsaPkcs1v15Signature(
    data,
    mismatchedSignature,
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(mismatch?.verified, false);
  assert.match(mismatch?.detail ?? "", /signature mismatch/i);

  const shortResult = await verifyRsaPkcs1v15Signature(
    data,
    signature.subarray(1),
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(shortResult?.verified, false);
  assert.match(shortResult?.detail ?? "", /length/i);

  const outOfRange = await verifyRsaPkcs1v15Signature(
    data,
    outOfRangeSignature,
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(outOfRange?.verified, false);
  assert.match(outOfRange?.detail ?? "", /outside the modulus/i);

  const equalToModulus = await verifyRsaPkcs1v15Signature(
    data,
    Uint8Array.of(3),
    rsaSpki(Uint8Array.of(3), Uint8Array.of(3)),
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(equalToModulus?.verified, false);
  assert.match(equalToModulus?.detail ?? "", /outside the modulus/i);
});

void test("verifyRsaPkcs1v15Signature treats malformed SPKI data as unknown", async () => {
  const chain = await createCertificateChain();
  const data = new TextEncoder().encode("binary101 malformed spki");
  const signature = await signWithNode(chain, "RSA-MD5", data);
  const validSpki = spkiBytes(chain.root.subjectPublicKeyInfo);

  await assertMalformedSpki(data, signature, spkiWithTopTag(validSpki));
  await assertMalformedSpki(data, signature, spkiWithAlgorithmTag(validSpki));
  await assertMalformedSpki(data, signature, spkiWithBitStringTag(validSpki));
  await assertMalformedSpki(data, signature, spkiWithWrongAlgorithmOid(validSpki));
  await assertMalformedSpki(data, signature, spkiWithNonZeroUnusedBits(validSpki));
  await assertMalformedSpki(data, signature, spkiWithRsaTopTag(validSpki));
  await assertMalformedSpki(data, signature, spkiWithModulusTag(validSpki));

  const unsupported = await verifyRsaPkcs1v15Signature(
    data,
    signature,
    chain.root.subjectPublicKeyInfo,
    signatureAlgorithm(SHA1_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(unsupported, undefined);
});

void test("verifyRsaPkcs1v15Signature rejects malformed RSA public integers", async () => {
  const data = new TextEncoder().encode("binary101 malformed rsa integers");

  const zeroModulus = await verifyRsaPkcs1v15Signature(
    data,
    Uint8Array.of(1),
    rsaSpki(Uint8Array.of(0), Uint8Array.of(3)),
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(zeroModulus?.verified, undefined);
  assert.match(zeroModulus?.detail ?? "", /Unable to parse RSA SubjectPublicKeyInfo/);

  const zeroExponent = await verifyRsaPkcs1v15Signature(
    data,
    Uint8Array.of(1),
    rsaSpki(Uint8Array.of(3), Uint8Array.of(0)),
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(zeroExponent?.verified, undefined);
  assert.match(zeroExponent?.detail ?? "", /Unable to parse RSA SubjectPublicKeyInfo/);

  const negativeModulus = await verifyRsaPkcs1v15Signature(
    data,
    Uint8Array.of(1),
    rsaSpki(Uint8Array.of(0x80), Uint8Array.of(3)),
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(negativeModulus?.verified, undefined);
  assert.match(negativeModulus?.detail ?? "", /Unable to parse RSA SubjectPublicKeyInfo/);

  const negativeExponent = await verifyRsaPkcs1v15Signature(
    data,
    Uint8Array.of(1),
    rsaSpki(Uint8Array.of(3), Uint8Array.of(0x80)),
    signatureAlgorithm(MD5_WITH_RSA_ENCRYPTION_OID)
  );
  assert.strictEqual(negativeExponent?.verified, undefined);
  assert.match(negativeExponent?.detail ?? "", /Unable to parse RSA SubjectPublicKeyInfo/);
});
