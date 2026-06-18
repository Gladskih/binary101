"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  Certificate,
  ContentInfo,
  SignedData
} from "../../../../../analyzers/pe/authenticode/pkijs-runtime.js";
import { verifyPkcs7Signatures } from "../../../../../analyzers/pe/authenticode/pkijs.js";
import { evaluateAuthenticodeTrustPolicy } from "../../../../../analyzers/pe/authenticode/trust-policy.js";
import { verifyAuthenticode } from "../../../../../analyzers/pe/authenticode/verify.js";
import type { AuthenticodeInfo } from "../../../../../analyzers/pe/authenticode/index.js";
import { OIW_SHA1_WITH_RSA_ENCRYPTION_OID } from "../../../../../analyzers/pe/authenticode/pkijs-support.js";
import type { AuthenticodeTrustStoreSnapshot } from "../../../../../analyzers/pe/authenticode/trust-store.js";
import { createSignedAuthenticodeCmsFixture } from "../../../../fixtures/pe-authenticode-signed-cms-fixtures.js";
import { signCertificateWithMd5Rsa } from "../../../../fixtures/pe-authenticode-md5-fixtures.js";
import {
  KEY_USAGE_DIGITAL_SIGNATURE,
  KEY_USAGE_KEY_CERT_SIGN,
  createBasicConstraintsExtension,
  createCertificate,
  createCommonName,
  createKeyUsageExtension,
  generateRsaKeyPair
} from "../../../../fixtures/pe-authenticode-cms-helpers.js";

const TRUST_SNAPSHOT_TIME = "2026-05-03T00:00:00.000Z";

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out.buffer;
};

const certificateThumbprint = async (certificate: Certificate): Promise<string> => {
  const der = certificate.toSchema().toBER(false);
  const digest = await crypto.subtle.digest("SHA-1", der);
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
};

const certificateDerBase64 = (certificate: Certificate): string =>
  Buffer.from(certificate.toSchema().toBER(false)).toString("base64");

const useLegacyOiwSha1RsaSignatureOid = (certificate: Certificate): void => {
  certificate.signatureAlgorithm.algorithmId = OIW_SHA1_WITH_RSA_ENCRYPTION_OID;
};

const readCertificateThumbprints = async (payload: Uint8Array): Promise<string[]> => {
  const contentInfo = ContentInfo.fromBER(toArrayBuffer(payload));
  const signedData = new SignedData({ schema: contentInfo.content });
  const certificates = (signedData.certificates ?? []).filter(
    (certificate): certificate is Certificate => certificate instanceof Certificate
  );
  return Promise.all(certificates.map(certificateThumbprint));
};

const createTrustStore = (trustedRoot: string, revokedCertificate: string): AuthenticodeTrustStoreSnapshot => ({
  schemaVersion: 1,
  generatedAt: TRUST_SNAPSHOT_TIME,
  source: "unit",
  trustedCAs: [{ thumbprint: trustedRoot, stores: ["Root"] }],
  revokedCAs: [{ thumbprint: revokedCertificate, stores: ["Disallowed"] }]
});

void test("verifyPkcs7Signatures annotates certificates from the Windows trust snapshot", async () => {
  const { payload } = await createSignedAuthenticodeCmsFixture();
  const thumbprints = await readCertificateThumbprints(payload);
  const verified = await verifyPkcs7Signatures(
    payload,
    createTrustStore(thumbprints[1] ?? "", thumbprints[2] ?? "")
  );

  assert.strictEqual(verified.trustPolicy?.generatedAt, TRUST_SNAPSHOT_TIME);
  assert.strictEqual(verified.trustPolicy?.certificates[0]?.status, "unknown");
  assert.strictEqual(verified.trustPolicy?.certificates[1]?.status, "trusted");
  assert.strictEqual(verified.trustPolicy?.certificates[2]?.status, "revoked");
});

void test("evaluateAuthenticodeTrustPolicy anchors an embedded issuer to a trusted root", async () => {
  const rootKeys = await generateRsaKeyPair();
  const intermediateKeys = await generateRsaKeyPair();
  const signerKeys = await generateRsaKeyPair();
  const root = await createCertificate(
    "Binary101 Root",
    1,
    rootKeys.publicKey,
    createCommonName("Binary101 Root"),
    rootKeys.privateKey,
    { notBefore: "2020-01-01T00:00:00Z", notAfter: "2035-01-01T00:00:00Z" },
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)]
  );
  const intermediate = await createCertificate(
    "Binary101 Intermediate",
    2,
    intermediateKeys.publicKey,
    root.subject,
    rootKeys.privateKey,
    { notBefore: "2021-01-01T00:00:00Z", notAfter: "2030-01-01T00:00:00Z" },
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)]
  );
  const signer = await createCertificate(
    "Binary101 Signer",
    3,
    signerKeys.publicKey,
    intermediate.subject,
    intermediateKeys.privateKey,
    { notBefore: "2022-01-01T00:00:00Z", notAfter: "2028-01-01T00:00:00Z" },
    [createBasicConstraintsExtension(false), createKeyUsageExtension(KEY_USAGE_DIGITAL_SIGNATURE)]
  );
  const rootThumbprint = await certificateThumbprint(root);
  const policy = await evaluateAuthenticodeTrustPolicy([signer, intermediate], {
    schemaVersion: 1,
    generatedAt: TRUST_SNAPSHOT_TIME,
    trustedCAs: [{
      thumbprint: rootThumbprint,
      subject: "CN=Binary101 Root",
      derBase64: certificateDerBase64(root),
      stores: ["Root"]
    }],
    revokedCAs: []
  });

  assert.strictEqual(policy?.certificates[0]?.status, "unknown");
  assert.strictEqual(policy?.certificates[1]?.status, "trusted");
  assert.strictEqual(policy?.certificates[1]?.anchorSha1Thumbprint, rootThumbprint);
  assert.strictEqual(policy?.certificates[1]?.anchorDerBase64, certificateDerBase64(root));
  assert.deepStrictEqual(policy?.certificates[1]?.stores, ["Root"]);
});

void test("evaluateAuthenticodeTrustPolicy accepts legacy OIW RSA/SHA-1 signature OID", async () => {
  const rootKeys = await generateRsaKeyPair("SHA-1");
  const intermediateKeys = await generateRsaKeyPair("SHA-1");
  const root = await createCertificate(
    "Binary101 Legacy Root",
    1,
    rootKeys.publicKey,
    createCommonName("Binary101 Legacy Root"),
    rootKeys.privateKey,
    { notBefore: "2020-01-01T00:00:00Z", notAfter: "2035-01-01T00:00:00Z" },
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)],
    "SHA-1"
  );
  const intermediate = await createCertificate(
    "Binary101 Legacy Intermediate",
    2,
    intermediateKeys.publicKey,
    root.subject,
    rootKeys.privateKey,
    { notBefore: "2021-01-01T00:00:00Z", notAfter: "2030-01-01T00:00:00Z" },
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)],
    "SHA-1"
  );
  useLegacyOiwSha1RsaSignatureOid(intermediate);

  const rootThumbprint = await certificateThumbprint(root);
  const policy = await evaluateAuthenticodeTrustPolicy([intermediate], {
    schemaVersion: 1,
    generatedAt: TRUST_SNAPSHOT_TIME,
    trustedCAs: [{
      thumbprint: rootThumbprint,
      subject: "CN=Binary101 Legacy Root",
      derBase64: certificateDerBase64(root),
      stores: ["Root"]
    }],
    revokedCAs: []
  });

  assert.strictEqual(policy?.certificates[0]?.status, "trusted");
  assert.strictEqual(policy?.certificates[0]?.anchorSha1Thumbprint, rootThumbprint);
  assert.strictEqual(policy?.warnings, undefined);
});

void test("evaluateAuthenticodeTrustPolicy verifies RSA/MD5 certificates against trusted anchors", async () => {
  const rootKeys = await generateRsaKeyPair();
  const intermediateKeys = await generateRsaKeyPair();
  const root = await createCertificate(
    "Binary101 MD5 Trust Root",
    1,
    rootKeys.publicKey,
    createCommonName("Binary101 MD5 Trust Root"),
    rootKeys.privateKey,
    { notBefore: "2020-01-01T00:00:00Z", notAfter: "2035-01-01T00:00:00Z" },
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)]
  );
  const intermediate = await createCertificate(
    "Binary101 MD5 Intermediate",
    2,
    intermediateKeys.publicKey,
    root.subject,
    rootKeys.privateKey,
    { notBefore: "2021-01-01T00:00:00Z", notAfter: "2030-01-01T00:00:00Z" },
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)]
  );
  await signCertificateWithMd5Rsa(intermediate, rootKeys.privateKey);

  const rootThumbprint = await certificateThumbprint(root);
  const policy = await evaluateAuthenticodeTrustPolicy([intermediate], {
    schemaVersion: 1,
    generatedAt: TRUST_SNAPSHOT_TIME,
    trustedCAs: [{
      thumbprint: rootThumbprint,
      subject: "CN=Binary101 MD5 Trust Root",
      derBase64: certificateDerBase64(root),
      stores: ["Root"]
    }],
    revokedCAs: []
  });

  assert.strictEqual(policy?.certificates[0]?.status, "trusted");
  assert.strictEqual(policy?.certificates[0]?.anchorSha1Thumbprint, rootThumbprint);
  assert.strictEqual(policy?.warnings, undefined);
});

void test("verifyAuthenticode removes the trust-anchor gap when a CA snapshot is available", async () => {
  const { core, digestHex, file, payload, securityDir } = await createSignedAuthenticodeCmsFixture();
  const thumbprints = await readCertificateThumbprints(payload);
  const auth: AuthenticodeInfo = {
    format: "pkcs7",
    fileDigestAlgorithmName: "sha256",
    fileDigest: digestHex
  };

  const verified = await verifyAuthenticode(
    file,
    core,
    securityDir,
    auth,
    payload,
    undefined,
    undefined,
    createTrustStore(thumbprints[1] ?? "", thumbprints[2] ?? "")
  );

  assert.ok(verified.trustPolicy);
  assert.ok(!verified.trustGaps?.some(gap => gap.id === "trust-anchor"));
  assert.ok(verified.trustGaps?.some(gap => gap.id === "revocation"));
});
