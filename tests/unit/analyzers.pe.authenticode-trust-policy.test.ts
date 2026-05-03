"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  Certificate,
  ContentInfo,
  SignedData
} from "../../analyzers/pe/authenticode/pkijs-runtime.js";
import { verifyPkcs7Signatures } from "../../analyzers/pe/authenticode/pkijs.js";
import { verifyAuthenticode } from "../../analyzers/pe/authenticode/verify.js";
import type { AuthenticodeInfo } from "../../analyzers/pe/authenticode/index.js";
import type { AuthenticodeTrustStoreSnapshot } from "../../analyzers/pe/authenticode/trust-store.js";
import { createSignedAuthenticodeCmsFixture } from "../fixtures/pe-authenticode-signed-cms-fixtures.js";

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
