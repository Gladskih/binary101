"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { attachPathChecks } from "../../analyzers/pe/authenticode/pkijs-path.js";
import type { AuthenticodeVerificationCheck } from "../../analyzers/pe/authenticode/index.js";
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
    "2020-01-01T00:00:00Z",
    "2035-01-01T00:00:00Z",
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)]
  );
  const g4RootName = createCommonName("G4 Root");
  const crossSignedG4Root = await createCertificate(
    "G4 Root",
    2,
    g4RootKeys.publicKey,
    assuredRoot.subject,
    assuredRootKeys.privateKey,
    "2021-01-01T00:00:00Z",
    "2035-01-01T00:00:00Z",
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)]
  );
  const selfSignedG4Root = await createCertificate(
    "G4 Root",
    3,
    g4RootKeys.publicKey,
    g4RootName,
    g4RootKeys.privateKey,
    "2021-01-01T00:00:00Z",
    "2035-01-01T00:00:00Z",
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)]
  );
  const signerCertificate = await createCertificate(
    "Binary101 Signer",
    4,
    signerKeys.publicKey,
    g4RootName,
    g4RootKeys.privateKey,
    "2023-01-01T00:00:00Z",
    "2030-01-01T00:00:00Z",
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
