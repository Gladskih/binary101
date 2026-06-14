"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  attachPathChecks,
  attachTimestampPathChecks
} from "../../analyzers/pe/authenticode/pkijs-path.js";
import type { AuthenticodeVerificationCheck } from "../../analyzers/pe/authenticode/index.js";
import type { Certificate } from "../../analyzers/pe/authenticode/pkijs-runtime.js";
import { OIW_SHA1_WITH_RSA_ENCRYPTION_OID } from "../../analyzers/pe/authenticode/pkijs-support.js";
import {
  CODE_SIGNING_EKU_OID,
  KEY_USAGE_DIGITAL_SIGNATURE,
  KEY_USAGE_KEY_CERT_SIGN,
  createBasicConstraintsExtension,
  createCertificate,
  createCommonName,
  createExtendedKeyUsageExtension,
  createKeyUsageExtension,
  generateRsaKeyPair
} from "../fixtures/pe-authenticode-cms-helpers.js";

const useLegacyOiwSha1RsaSignatureOid = (certificate: Certificate): void => {
  certificate.signatureAlgorithm.algorithmId = OIW_SHA1_WITH_RSA_ENCRYPTION_OID;
};

const createAmbiguousIssuerFixture = async () => {
  const assuredRootKeys = await generateRsaKeyPair();
  const g4RootKeys = await generateRsaKeyPair();
  const signerKeys = await generateRsaKeyPair();
  const assuredRoot = await createCertificate(
    "Assured Root",
    1,
    assuredRootKeys.publicKey,
    createCommonName("Assured Root"),
    assuredRootKeys.privateKey,
    { notBefore: "2020-01-01T00:00:00Z", notAfter: "2035-01-01T00:00:00Z" },
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)]
  );
  const g4RootName = createCommonName("G4 Root");
  const crossSignedG4Root = await createCertificate(
    "G4 Root",
    2,
    g4RootKeys.publicKey,
    assuredRoot.subject,
    assuredRootKeys.privateKey,
    { notBefore: "2021-01-01T00:00:00Z", notAfter: "2035-01-01T00:00:00Z" },
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)]
  );
  const selfSignedG4Root = await createCertificate(
    "G4 Root",
    3,
    g4RootKeys.publicKey,
    g4RootName,
    g4RootKeys.privateKey,
    { notBefore: "2021-01-01T00:00:00Z", notAfter: "2035-01-01T00:00:00Z" },
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)]
  );
  const signerCertificate = await createCertificate(
    "Binary101 Signer",
    4,
    signerKeys.publicKey,
    g4RootName,
    g4RootKeys.privateKey,
    { notBefore: "2023-01-01T00:00:00Z", notAfter: "2030-01-01T00:00:00Z" },
    [
      createBasicConstraintsExtension(false),
      createKeyUsageExtension(KEY_USAGE_DIGITAL_SIGNATURE),
      createExtendedKeyUsageExtension(CODE_SIGNING_EKU_OID)
    ]
  );
  return [signerCertificate, crossSignedG4Root, selfSignedG4Root];
};

void test(
  "attachPathChecks prefers a self-signed issuer over an equally-valid cross-signed variant",
  async () => {
    const checks: AuthenticodeVerificationCheck[] = [];
    const certificates = await createAmbiguousIssuerFixture();

    const pathIndexes = await attachPathChecks(
      checks,
      "Signer 1",
      certificates,
      0,
      undefined,
      "signing time"
    );

    assert.deepStrictEqual(pathIndexes, [0, 2]);
    assert.ok(
      checks.some(
        check =>
          check.id === "Signer 1-certificate-1-issuer-match" &&
          /certificate 3 subject/i.test(check.title)
      )
    );
    assert.ok(
      checks.some(
        check => check.id === "Signer 1-certificate-3-self-signed" && check.status === "pass"
      )
    );
    assert.ok(
      !checks.some(
        check =>
          check.id === "Signer 1-certificate-2-issuer-match" &&
          check.detail === "No presented issuer certificate matches the issuer DN."
      )
    );
  }
);

void test("attachTimestampPathChecks applies timestamp validity only to the leaf", async () => {
  const checks: AuthenticodeVerificationCheck[] = [];
  const certificates = await createAmbiguousIssuerFixture();

  const pathIndexes = await attachTimestampPathChecks(
    checks,
    "Signer 1",
    certificates,
    0,
    "2024-01-01T00:00:00.000Z"
  );

  assert.deepStrictEqual(pathIndexes, [0, 2]);
  assert.ok(checks.some(check => check.id === "Signer 1-certificate-1-timestamp time-validity"));
  assert.ok(!checks.some(check => check.id === "Signer 1-certificate-3-timestamp time-validity"));
});

void test("attachPathChecks verifies self-signed certificates with legacy OIW RSA/SHA-1 OID", async () => {
  const checks: AuthenticodeVerificationCheck[] = [];
  const rootKeys = await generateRsaKeyPair("SHA-1");
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
  useLegacyOiwSha1RsaSignatureOid(root);

  const pathIndexes = await attachPathChecks(checks, "Signer 1", [root], 0, undefined, "signing time");

  assert.deepStrictEqual(pathIndexes, [0]);
  assert.ok(
    checks.some(check => check.id === "Signer 1-certificate-1-self-signed" && check.status === "pass")
  );
});
