"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderAuthenticodeTree } from "../../renderers/pe/security-tree.js";

void test("renderAuthenticodeTree renders signer and countersignature certificate paths", () => {
  const html = renderAuthenticodeTree({
    offset: 0,
    length: 128,
    availableBytes: 128,
    revision: 0x0200,
    revisionName: "Revision 2.0",
    certificateType: 0x0002,
    typeName: "PKCS#7 SignedData (Authenticode)",
    authenticode: {
      format: "pkcs7",
      signers: [
        {
          issuer: "CN=Issuer CA",
          digestAlgorithmName: "sha256"
        }
      ],
      certificates: [
        {
          subject: "CN=Leaf Signer",
          issuer: "CN=Issuer CA",
          notBefore: "2024-01-01T00:00:00Z",
          notAfter: "2026-01-01T00:00:00Z",
          derBase64: "AQID"
        },
        {
          subject: "CN=Issuer CA",
          issuer: "CN=Root CA",
          notBefore: "2023-01-01T00:00:00Z",
          notAfter: "2030-01-01T00:00:00Z"
        },
        {
          subject: "CN=Root CA",
          issuer: "CN=Root CA",
          notBefore: "2020-01-01T00:00:00Z",
          notAfter: "2035-01-01T00:00:00Z"
        },
        {
          subject: "CN=Timestamp Leaf",
          issuer: "CN=Timestamp CA",
          notBefore: "2024-01-01T00:00:00Z",
          notAfter: "2028-01-01T00:00:00Z"
        },
        {
          subject: "CN=Timestamp CA",
          issuer: "CN=Root CA",
          notBefore: "2023-01-01T00:00:00Z",
          notAfter: "2030-01-01T00:00:00Z"
        }
      ],
      verification: {
        signerVerifications: [
          {
            index: 0,
            signatureVerified: true,
            signerCertificateIndex: 0,
            certificatePathIndexes: [0, 1, 2],
            countersignatures: [
              {
                index: 0,
                signerCertificateIndex: 3,
                certificatePathIndexes: [3, 4, 2],
                signingTime: "2024-06-01T12:00:00Z",
                signatureVerified: true,
                messageDigestVerified: true
              }
            ]
          }
        ]
      }
    }
  });

  assert.ok(html.includes("Certificate tree"));
  assert.ok(html.includes("Signer 1: CN=Leaf Signer"));
  assert.ok(html.includes("Certificate &#8470;1: CN=Leaf Signer"));
  assert.ok(html.includes("Signer cert"));
  assert.ok(html.includes("Countersignature 1"));
  assert.ok(html.includes("Timestamp cert"));
  assert.ok(html.includes("Root"));
  assert.ok(html.includes("Sig"));
  assert.ok(html.includes("data-certificate-download"));
  assert.ok(html.includes("authenticode-certificate-1.cer"));
});

void test("renderAuthenticodeTree shows Windows CA trust snapshot verdicts", () => {
  const html = renderAuthenticodeTree({
    offset: 0,
    length: 128,
    availableBytes: 128,
    revision: 0x0200,
    revisionName: "Revision 2.0",
    certificateType: 0x0002,
    typeName: "PKCS#7 SignedData (Authenticode)",
    authenticode: {
      format: "pkcs7",
      certificates: [
        { subject: "CN=Leaf", issuer: "CN=Root" },
        { subject: "CN=Root", issuer: "CN=Root" },
        { subject: "CN=Timestamp", issuer: "CN=Root" }
      ],
      verification: {
        trustPolicy: {
          generatedAt: "2026-05-03T00:00:00.000Z",
          source: "unit",
          certificates: [
            { certificateIndex: 0, status: "unknown", sha1Thumbprint: "AA" },
            {
              certificateIndex: 1,
              status: "trusted",
              sha1Thumbprint: "BB",
              anchorDerBase64: "BAUG",
              anchorSha1Thumbprint: "DD",
              anchorSubject: "CN=Trusted Root",
              stores: ["Root"]
            },
            {
              certificateIndex: 2,
              status: "revoked",
              sha1Thumbprint: "CC",
              stores: ["Disallowed"]
            }
          ]
        },
        signerVerifications: [
          {
            index: 0,
            signerCertificateIndex: 0,
            certificatePathIndexes: [0, 1],
            countersignatures: [
              {
                index: 0,
                signerCertificateIndex: 2,
                certificatePathIndexes: [2]
              }
            ]
          }
        ]
      }
    }
  });

  assert.ok(html.includes("Trust snapshot"));
  assert.ok(html.includes("2026-05-03T00:00:00.000Z"));
  assert.ok(html.includes("Trusted"));
  assert.ok(html.includes("Revoked"));
  assert.ok(html.includes("Not in store"));
  assert.ok(html.includes("SHA-1"));
  assert.ok(html.includes("Disallowed"));
  assert.ok(html.includes("Trust anchor: CN=Trusted Root"));
  assert.ok(html.includes("authenticode-trust-anchor-DD.cer"));
});

void test("renderAuthenticodeTree omits output when signer verification paths are unavailable", () => {
  assert.strictEqual(
    renderAuthenticodeTree({
      offset: 0,
      length: 8,
      availableBytes: 8,
      revision: 0,
      revisionName: "Revision 0x0000",
      certificateType: 0,
      typeName: "Type 0x0000"
    }),
    ""
  );
});
