"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSecurity } from "../../renderers/pe/security-view.js";

void test("renderSecurity renders details when present", () => {
  const cert = {
    offset: 0,
    length: 32,
    availableBytes: 16,
    revision: 0x0300,
    revisionName: "Revision 0x0300",
    certificateType: 0xf00d,
    typeName: "Type 0xf00d",
    authenticode: {
      format: "pkcs7" as const,
      contentTypeName: "PKCS#7 signedData",
      payloadContentTypeName: "1.2.3.4",
      digestAlgorithms: ["sha256", "md5"],
      signerCount: 2,
      certificateCount: 3
    },
    warnings: ["Length field does not match directory entry size."]
  };
  const security: Parameters<typeof renderSecurity>[0] = { count: 1, certs: [cert] };
  const out: string[] = [];
  renderSecurity(security, out);
  const html = out.join("");
  assert.ok(html.includes("Certificate records"));
  assert.ok(html.includes("Certificate #1"));
  assert.ok(html.includes("Type 0xf00d"));
  assert.ok(html.includes("1.2.3.4"));
  assert.ok(!html.includes("Show certificates"));
  assert.ok(html.includes("sha256"));
  assert.ok(html.includes("md5"));
  assert.ok(html.includes("truncated"));
  assert.ok(html.includes("Signature integrity check unavailable"));
  assert.ok(html.includes("No cryptographic verification result is attached"));
  assert.ok(html.includes("Structural warnings"));
  assert.ok(html.includes("Length field does not match directory entry size."));
});

void test("renderSecurity includes expanded Authenticode details", () => {
  const cert = {
    offset: 0,
    length: 32,
    availableBytes: 32,
    revision: 0x0200,
    revisionName: "Revision 2.0",
    certificateType: 0x0002,
    typeName: "PKCS#7 SignedData (Authenticode)",
    authenticode: {
      format: "pkcs7" as const,
      contentTypeName: "PKCS#7 signedData",
      payloadContentTypeName: "SPC_INDIRECT_DATA",
      digestAlgorithms: ["sha256"],
      fileDigestAlgorithmName: "sha256",
      fileDigest: "deadbeef",
      verification: {
        computedFileDigest: "deadbeef",
        fileDigestMatches: true,
        signerVerifications: [{ index: 0, signatureVerified: true, code: 14 }],
        warnings: ["synthetic verification warning"]
      },
      signerCount: 1,
      certificateCount: 1,
      signers: [
        {
          issuer: "CN=Test Issuer",
          serialNumber: "1234",
          digestAlgorithmName: "sha256",
          signatureAlgorithmName: "rsaEncryption",
          signingTime: "2024-01-01T00:00:00Z"
        }
      ],
      certificates: [
        {
          subject: "CN=Test Subject",
          issuer: "CN=Test Issuer",
          serialNumber: "1234",
          notBefore: "2024-01-01T00:00:00Z",
          notAfter: "2025-01-01T00:00:00Z"
        }
      ]
    }
  };
  const security: Parameters<typeof renderSecurity>[0] = { count: 1, certs: [cert] };
  const out: string[] = [];
  renderSecurity(security, out);
  const html = out.join("");
  assert.ok(html.includes("peSecurityValidation--ok"));
  assert.ok(html.includes("Signature integrity check passed"));
  assert.ok(html.includes("Embedded file digest matches this file"));
  assert.ok(html.includes("all CMS signer signatures verified"));
  assert.ok(html.includes("This checks signature integrity only."));
  assert.ok(
    html.includes("Certificate-chain trust, revocation, EKU, and local platform trust")
  );
  assert.ok(html.includes("Embedded file digest (sha256)"));
  assert.ok(html.includes("Computed file digest (sha256)"));
  assert.ok(html.includes("Digest match"));
  assert.ok(html.includes("PKCS#7"));
  assert.ok(html.includes("SPC_INDIRECT_DATA"));
  assert.ok(html.includes("sha256"));
  assert.ok(html.includes("opt sel"));
  assert.ok(html.includes("Signer 1: signature verified."));
  assert.ok(html.includes("<b>Signer 1</b>:"));
  assert.ok(html.includes("Issuer CN=Test Issuer"));
  assert.ok(html.includes("<b>Certificate 1</b>:"));
  assert.ok(html.includes("Subject CN=Test Subject"));
  assert.ok(html.includes("synthetic verification warning"));
  assert.ok(!html.includes("PKI.js code 14"));
});

void test("renderSecurity renders count without certificate table", () => {
  const security: Parameters<typeof renderSecurity>[0] = { count: 0, certs: [] };
  const out: string[] = [];
  renderSecurity(security, out);
  const html = out.join("");
  assert.ok(html.includes("Certificate records"));
  assert.ok(!html.includes("<table"));
});

void test("renderSecurity renders top-level directory warnings", () => {
  const security: Parameters<typeof renderSecurity>[0] = {
    count: 0,
    certs: [],
    warnings: ["Attribute certificate table is truncated by end of file."]
  };
  const out: string[] = [];
  renderSecurity(security, out);
  const html = out.join("");
  assert.ok(html.includes("Attribute certificate table is truncated by end of file."));
  assert.ok(html.includes("<ul"));
});

void test("renderSecurity tolerates missing fields and renders negative matches", () => {
  const certWithGaps = {
    offset: 0,
    length: 32,
    availableBytes: 32,
    revision: 0x0200,
    revisionName: "Revision 2.0",
    certificateType: 0x0002,
    typeName: "PKCS#7 SignedData (Authenticode)",
    authenticode: {
      format: "pkcs7" as const,
      fileDigestAlgorithm: "sha256",
      fileDigest: "deadbeef",
      verification: { fileDigestMatches: false },
      signers: [{ digestAlgorithm: "sha256", signatureAlgorithm: "rsaEncryption" }],
      certificates: [{ notAfter: "2025-01-01T00:00:00Z" }]
    }
  };
  const bareCert = {
    offset: 32,
    length: 8,
    availableBytes: 8,
    revision: 0,
    revisionName: "Revision 0x0000",
    certificateType: 0,
    typeName: "Type 0x0000"
  };
  const security: Parameters<typeof renderSecurity>[0] = {
    count: 2,
    certs: [certWithGaps, bareCert]
  };
  const out: string[] = [];
  renderSecurity(security, out);
  const html = out.join("");
  assert.ok(html.includes("peSecurityValidation--warn"));
  assert.ok(html.includes("Signature integrity check failed"));
  assert.ok(html.includes("embedded file digest does not match this file"));
  assert.ok(html.includes("Digest match"));
});
