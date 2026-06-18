"use strict";

import * as asn1js from "asn1js";
import assert from "node:assert/strict";
import { createHash, createPrivateKey, sign as nodeSign } from "node:crypto";
import { test } from "node:test";
import { verifySignedDataSignerWithLocalRsa } from "../../../../../analyzers/pe/authenticode/pkijs-local-rsa.js";
import type { Certificate, SignedData, SignerInfo } from "../../../../../analyzers/pe/authenticode/pkijs-runtime.js";
import { readOctetStringBytes } from "../../../../../analyzers/pe/authenticode/pkijs-support.js";
import {
  CMS_MESSAGE_DIGEST_OID,
  setEncodedSignedAttributes,
  toArrayBuffer
} from "../../../../fixtures/pe-authenticode-cms-helpers.js";
import {
  MD5_DIGEST_OID,
  MD5_WITH_RSA_ENCRYPTION_OID,
  publicKeyInfoFromDer
} from "../../../../fixtures/pe-authenticode-rsa-helpers.js";
import {
  createCertificateChain,
  createSignedData
} from "../../../../fixtures/pe-authenticode-signed-cms-fixtures.js";

type CertificateChain = Awaited<ReturnType<typeof createCertificateChain>>;

const signWithNode = async (
  chain: CertificateChain,
  data: Uint8Array | ArrayBuffer
): Promise<Uint8Array> => {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", chain.signerPrivateKey);
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
  return new Uint8Array(nodeSign("RSA-MD5", Buffer.from(bytes), createPrivateKey({
    key: Buffer.from(pkcs8),
    format: "der",
    type: "pkcs8"
  })));
};

const readContent = (signedData: SignedData): Uint8Array => {
  const content = readOctetStringBytes(signedData.encapContentInfo.eContent);
  assert.ok(content);
  return content;
};

const setMessageDigest = (signer: SignerInfo, digest: Uint8Array): void => {
  const attribute = signer.signedAttrs?.attributes.find(item => item.type === CMS_MESSAGE_DIGEST_OID);
  assert.ok(attribute);
  attribute.values = [new asn1js.OctetString({ valueHex: toArrayBuffer(digest) })];
  assert.ok(signer.signedAttrs);
  setEncodedSignedAttributes(signer.signedAttrs);
};

const signCurrentAttributes = async (
  chain: CertificateChain,
  signer: SignerInfo
): Promise<void> => {
  assert.ok(signer.signedAttrs);
  signer.signature = new asn1js.OctetString({
    valueHex: toArrayBuffer(await signWithNode(chain, signer.signedAttrs.encodedValue))
  });
};

const createLocalMd5SignedData = async () => {
  const chain = await createCertificateChain();
  const signedData = await createSignedData("00", chain);
  const signer = signedData.signerInfos[0];
  assert.ok(signer);
  signer.digestAlgorithm.algorithmId = MD5_DIGEST_OID;
  signer.digestAlgorithm.algorithmParams = new asn1js.Null();
  signer.signatureAlgorithm.algorithmId = MD5_WITH_RSA_ENCRYPTION_OID;
  signer.signatureAlgorithm.algorithmParams = new asn1js.Null();
  setMessageDigest(signer, createHash("md5").update(readContent(signedData)).digest());
  await signCurrentAttributes(chain, signer);
  return { chain, signedData, signer };
};

void test("verifySignedDataSignerWithLocalRsa verifies local RSA/MD5 CMS signed attributes", async () => {
  const { chain, signedData, signer } = await createLocalMd5SignedData();

  const result = await verifySignedDataSignerWithLocalRsa(signedData, signer, chain.signer);

  assert.strictEqual(result?.signatureVerified, true);
  assert.match(result?.message ?? "", /legacy RSA\/MD5/i);
});

void test("verifySignedDataSignerWithLocalRsa skips signers PKI.js can verify", async () => {
  const chain = await createCertificateChain();
  const signedData = await createSignedData("00", chain);
  const signer = signedData.signerInfos[0];
  assert.ok(signer);

  const result = await verifySignedDataSignerWithLocalRsa(signedData, signer, chain.signer);

  assert.strictEqual(result, undefined);
});

void test("verifySignedDataSignerWithLocalRsa does not inspect unsupported signers", async () => {
  const chain = await createCertificateChain();
  const signedData = await createSignedData("00", chain);
  const signer = signedData.signerInfos[0];
  assert.ok(signer);
  setMessageDigest(signer, Uint8Array.of(0xde, 0xad, 0xbe, 0xef));

  const result = await verifySignedDataSignerWithLocalRsa(signedData, signer, chain.signer);

  assert.strictEqual(result, undefined);
});

void test("verifySignedDataSignerWithLocalRsa checks messageDigest before the RSA signature", async () => {
  const { chain, signedData, signer } = await createLocalMd5SignedData();
  setMessageDigest(signer, Uint8Array.of(0xde, 0xad, 0xbe, 0xef));
  await signCurrentAttributes(chain, signer);

  const result = await verifySignedDataSignerWithLocalRsa(signedData, signer, chain.signer);

  assert.strictEqual(result?.signatureVerified, false);
  assert.match(result?.message ?? "", /messageDigest mismatch/i);
});

void test("verifySignedDataSignerWithLocalRsa reports missing local CMS inputs", async () => {
  const missingDigestFixture = await createLocalMd5SignedData();
  const missingDigestAttrs = missingDigestFixture.signer.signedAttrs;
  assert.ok(missingDigestAttrs);
  missingDigestAttrs.attributes.splice(
    missingDigestAttrs.attributes.findIndex(attribute => attribute.type === CMS_MESSAGE_DIGEST_OID),
    1
  );
  setEncodedSignedAttributes(missingDigestAttrs);

  const { chain, signedData, signer } = await createLocalMd5SignedData();
  const missingDigest = await verifySignedDataSignerWithLocalRsa(
    missingDigestFixture.signedData,
    missingDigestFixture.signer,
    missingDigestFixture.chain.signer
  );
  assert.strictEqual(missingDigest?.signatureVerified, false);
  assert.match(missingDigest?.message ?? "", /messageDigest signed attribute is absent/i);

  signer.digestAlgorithm.algorithmId = "1.2.3.4";
  const unsupportedDigest = await verifySignedDataSignerWithLocalRsa(signedData, signer, chain.signer);
  assert.strictEqual(unsupportedDigest?.signatureVerified, false);
  assert.match(unsupportedDigest?.message ?? "", /Unsupported digest algorithm OID 1\.2\.3\.4/i);

  const missingContentFixture = await createLocalMd5SignedData();
  delete missingContentFixture.signedData.encapContentInfo.eContent;
  const missingContent = await verifySignedDataSignerWithLocalRsa(
    missingContentFixture.signedData,
    missingContentFixture.signer,
    missingContentFixture.chain.signer
  );
  assert.strictEqual(missingContent?.signatureVerified, false);
  assert.match(missingContent?.message ?? "", /Signed content bytes are absent/i);
});

void test("verifySignedDataSignerWithLocalRsa preserves unknown local RSA results", async () => {
  const { chain, signedData, signer } = await createLocalMd5SignedData();
  const badCertificate = {
    ...chain.signer,
    subjectPublicKeyInfo: publicKeyInfoFromDer(Uint8Array.of(0x05, 0x00))
  } as Certificate;

  const result = await verifySignedDataSignerWithLocalRsa(signedData, signer, badCertificate);

  assert.strictEqual(Object.hasOwn(result ?? {}, "signatureVerified"), false);
  assert.match(result?.message ?? "", /Unable to parse RSA SubjectPublicKeyInfo/);
});

void test("verifySignedDataSignerWithLocalRsa reports absent direct signature input", async () => {
  const { chain, signedData, signer } = await createLocalMd5SignedData();
  delete signedData.encapContentInfo.eContent;
  delete signer.signedAttrs;

  const result = await verifySignedDataSignerWithLocalRsa(signedData, signer, chain.signer);

  assert.strictEqual(Object.hasOwn(result ?? {}, "signatureVerified"), false);
  assert.match(result?.message ?? "", /CMS signature input bytes are absent/i);
});

void test("verifySignedDataSignerWithLocalRsa supports detached and direct-content signatures", async () => {
  const { chain, signedData, signer } = await createLocalMd5SignedData();
  const externalData = readContent(signedData).slice();
  delete signedData.encapContentInfo.eContent;
  let result = await verifySignedDataSignerWithLocalRsa(signedData, signer, chain.signer, externalData);
  assert.strictEqual(result?.signatureVerified, true);

  delete signer.signedAttrs;
  signer.signature = new asn1js.OctetString({
    valueHex: toArrayBuffer(await signWithNode(chain, externalData))
  });
  result = await verifySignedDataSignerWithLocalRsa(signedData, signer, chain.signer, externalData);
  assert.strictEqual(result?.signatureVerified, true);
});
