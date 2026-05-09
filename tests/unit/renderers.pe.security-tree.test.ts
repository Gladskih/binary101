"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderAuthenticodeTree } from "../../renderers/pe/security-tree.js";

const getNodeClassForTitle = (html: string, title: string): string | undefined => {
  const titleIndex = html.indexOf(`>${title}</div>`);
  if (titleIndex < 0) return undefined;
  const nodeIndex = html.slice(0, titleIndex).lastIndexOf(`<div class="peSecurityTreeNode `);
  return html.slice(nodeIndex, titleIndex).match(/class="([^"]+)"/)?.[1];
};

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
            ],
            timestampTokens: [
              {
                index: 0,
                signerCertificateIndex: 0,
                certificatePathIndexes: [0, 1],
                signingTime: "2024-06-01T12:01:00Z",
                signatureVerified: true,
                messageDigestVerified: true,
                certificates: [
                  {
                    subject: "CN=RFC3161 Timestamp Leaf",
                    issuer: "CN=RFC3161 Timestamp CA",
                    notBefore: "2024-01-01T00:00:00Z",
                    notAfter: "2028-01-01T00:00:00Z"
                  },
                  {
                    subject: "CN=RFC3161 Timestamp CA",
                    issuer: "CN=RFC3161 Timestamp CA",
                    notBefore: "2023-01-01T00:00:00Z",
                    notAfter: "2030-01-01T00:00:00Z"
                  }
                ]
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
  assert.ok(html.includes("RFC3161 timestamp 1"));
  assert.ok(html.includes("Certificate &#8470;1: CN=RFC3161 Timestamp Leaf"));
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
        { subject: "CN=Root", issuer: "CN=External Root" },
        { subject: "CN=Timestamp", issuer: "CN=Root" },
        { subject: "CN=Unknown Leaf", issuer: "CN=Unknown CA" },
        { subject: "CN=Unknown CA", issuer: "CN=Unknown CA" },
        { subject: "CN=External Root", issuer: "CN=External Root" },
        { subject: "CN=Root", issuer: "CN=Trusted Root" }
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
            },
            { certificateIndex: 3, status: "unknown", sha1Thumbprint: "EE" },
            {
              certificateIndex: 4,
              status: "unknown",
              sha1Thumbprint: "FF"
            },
            { certificateIndex: 5, status: "unknown", sha1Thumbprint: "11" },
            {
              certificateIndex: 6,
              status: "trusted",
              sha1Thumbprint: "22",
              anchorDerBase64: "CAkK",
              anchorSha1Thumbprint: "33",
              anchorSubject: "CN=Trusted Root",
              stores: ["Root"]
            }
          ]
        },
        signerVerifications: [
          {
            index: 0,
            signerCertificateIndex: 0,
            certificatePathIndexes: [0, 1, 5],
            countersignatures: [
              {
                index: 0,
                signerCertificateIndex: 2,
                certificatePathIndexes: [2]
              }
            ]
          },
          {
            index: 1,
            signerCertificateIndex: 3,
            certificatePathIndexes: [3, 4]
          }
        ]
      }
    }
  });

  assert.ok(html.includes("Trust snapshot"));
  assert.ok(html.includes("2026-05-03T00:00:00.000Z"));
  assert.ok(html.includes("Chain trusted"));
  assert.ok(html.includes("In store"));
  assert.ok(html.includes("Disallowed chain"));
  assert.ok(html.includes("Not trusted"));
  assert.ok(html.includes("SHA-1"));
  assert.ok(html.includes("Disallowed"));
  assert.ok(html.includes("Trust anchor: CN=Trusted Root"));
  assert.ok(html.includes("authenticode-trust-anchor-DD.cer"));
  assert.equal(
    getNodeClassForTitle(html, "Certificate &#8470;1: CN=Leaf"),
    "peSecurityTreeNode peSecurityTreeNode--pass"
  );
  assert.equal(
    getNodeClassForTitle(html, "Certificate &#8470;4: CN=Unknown Leaf"),
    "peSecurityTreeNode peSecurityTreeNode--unknown"
  );
  assert.equal(
    getNodeClassForTitle(html, "Certificate &#8470;6: CN=External Root"),
    "peSecurityTreeNode peSecurityTreeNode--unknown"
  );
  assert.equal(
    getNodeClassForTitle(html, "Certificate &#8470;7: CN=Root"),
    "peSecurityTreeNode peSecurityTreeNode--pass"
  );
  assert.ok(html.includes("authenticode-trust-anchor-33.cer"));
  assert.equal(html.includes("Not in store"), false);
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
