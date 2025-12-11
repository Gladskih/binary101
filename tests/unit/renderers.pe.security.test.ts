"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSecurity } from "../../renderers/pe/directories.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

void test("renderSecurity skips when security block is missing and renders details when present", () => {
  const emptyOut: string[] = [];
  renderSecurity({} as PeParseResult, emptyOut);
  assert.strictEqual(emptyOut.length, 0);

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
  const pe = { security: { count: 1, certs: [cert] } } as unknown as PeParseResult;
  const out: string[] = [];
  renderSecurity(pe, out);
  const html = out.join("");
  assert.ok(html.includes("Certificate records"));
  assert.ok(html.includes("Type 0xf00d"));
  assert.ok(html.includes("Signers: 2"));
  assert.ok(html.includes("Certificates: 3"));
  assert.ok(html.includes("truncated"));
  assert.ok(html.includes("⚠"));
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
  const pe = { security: { count: 1, certs: [cert] } } as unknown as PeParseResult;
  const out: string[] = [];
  renderSecurity(pe, out);
  const html = out.join("");
  assert.ok(html.includes("File digest (sha256): deadbeef"));
  assert.ok(html.includes("Signer 1:"));
  assert.ok(html.includes("Issuer CN=Test Issuer"));
  assert.ok(html.includes("Certificate 1:"));
  assert.ok(html.includes("Subject CN=Test Subject"));
});

void test("renderSecurity renders count without certificate table", () => {
  const pe = { security: { count: 0, certs: [] } } as unknown as PeParseResult;
  const out: string[] = [];
  renderSecurity(pe, out);
  const html = out.join("");
  assert.ok(html.includes("Certificate records"));
  assert.ok(!html.includes("<table"));
});
