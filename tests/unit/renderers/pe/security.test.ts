"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSecurity } from "../../../../renderers/pe/security-view.js";
import { decodeWinCertificate } from "../../../../analyzers/pe/authenticode/index.js";
import {
  createCmsDigestAlgorithmFixture,
  wrapCmsDigestWinCertificate
} from "../../../fixtures/cms-digest-algorithms.js";

// Microsoft WIN_CERTIFICATE / WinTrust.h and UEFI 2.10 section 32.2.4 define these codes.
// https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-win_certificate
// https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html#win-certificate
for (const [certificateType, label, explanation] of [
  [0x0001, "X.509", "Individual X.509 certificate blob. Payload is not decoded or verified."],
  [0x0002, "PKCS#7", "Authenticode SignedData / CMS signature."],
  [0x0004, "TS stack", "Terminal Services stack signing certificate. Payload is not decoded or verified."],
  [0x0009, "PKCS1_SIGN", "WIN_CERT_TYPE_PKCS1_SIGN, documented by Microsoft Learn. Payload is not decoded or verified."],
  [0x0ef0, "EFI PKCS#1 v1.5", "UEFI RSASSA-PKCS1-v1_5 signature. Payload is not decoded or verified."],
  [0x0ef1, "EFI GUID", "UEFI certificate with a GUID-defined payload format. Payload is not decoded or verified."]
] as const) {
  void test(`renderSecurity selects the declared certificate type ${certificateType}`, () => {
    const bytes = wrapCmsDigestWinCertificate(
      createCmsDigestAlgorithmFixture([], []), certificateType
    );
    const out: string[] = [];

    renderSecurity({ count: 1, certs: [decodeWinCertificate(bytes, bytes.length, 0)] }, out);

    assert.ok(out.join("").includes(
      `class="opt sel" data-accessible-tooltip title="${label} - ${explanation} ` +
      `(0x${certificateType.toString(16).padStart(4, "0")})">${label}</span>`
    ));
    assert.equal(out.join("").includes("Certificate tree"), certificateType === 0x0002);
  });
}

for (const certificateType of [0x000a, 0x0ef2]) {
  void test(`renderSecurity preserves unconfirmed certificate type ${certificateType} numerically`, () => {
    const bytes = wrapCmsDigestWinCertificate(
      createCmsDigestAlgorithmFixture([], []), certificateType
    );
    const out: string[] = [];

    renderSecurity({ count: 1, certs: [decodeWinCertificate(bytes, bytes.length, 0)] }, out);

    assert.ok(out.join("").includes(`Type 0x${certificateType.toString(16).padStart(4, "0")}`));
    assert.ok(!out.join("").includes('class="opt '));
    assert.ok(!out.join("").includes("Certificate tree"));
  });
}

void test("renderSecurity displays parsed CMS digest consistency warnings", () => {
  // NIST CSOR: SHA-256 and SHA-512 hash algorithm OIDs.
  // https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
  const bytes = wrapCmsDigestWinCertificate(createCmsDigestAlgorithmFixture(
    ["2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.3"],
    ["2.16.840.1.101.3.4.2.1"]
  ));
  const out: string[] = [];

  renderSecurity({ count: 1, certs: [decodeWinCertificate(bytes, bytes.length, 0)] }, out);

  assert.ok(out.join("").includes("Structural warnings"));
  assert.ok(out.join("").includes("SignedData digestAlgorithms lists sha512, but no SignerInfo uses it"));
});

const EXPANDED_AUTHENTICODE_SECURITY: Parameters<typeof renderSecurity>[0] = {
  count: 1,
  certs: [{
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
        signerVerifications: [{
          index: 0,
          signatureVerified: true,
          signerCertificateIndex: 0,
          certificatePathIndexes: [0],
          countersignatures: [{
            index: 0,
            signerCertificateIndex: 1,
            certificatePathIndexes: [1],
            signingTime: "2024-01-01T00:05:00Z",
            signatureVerified: true,
            messageDigestVerified: true
          }]
        }],
        checks: [
          { id: "file-digest-match", status: "pass" as const, title: "Embedded file digest matches the computed PE Authenticode digest", detail: "deadbeef" },
          { id: "Signer 1-signature", status: "pass" as const, title: "Signer 1: CMS signature verifies" },
          { id: "Signer 1-certificate", status: "pass" as const, title: "Signer 1: signer certificate is present in the embedded chain" },
          { id: "Signer 1-key-usage", status: "pass" as const, title: "Signer 1: certificate permits digital signatures" },
          { id: "Signer 1-eku", status: "pass" as const, title: "Signer 1: certificate permits code signing" },
          { id: "Signer 1 countersignature 1-signature", status: "pass" as const, title: "Signer 1 countersignature 1: CMS signature verifies" },
          { id: "Signer 1 countersignature 1-certificate", status: "pass" as const, title: "Signer 1 countersignature 1: signer certificate is present in the embedded chain" },
          { id: "Signer 1 countersignature 1-message-digest", status: "unknown" as const, title: "Signer 1 countersignature 1: signed attributes message digest matches the parent signature", detail: "PKI.js crypto engine is unavailable." },
          { id: "Signer 1-countersignature-1-chronology", status: "unknown" as const, title: "Signer 1: countersignature 1 is not earlier than the claimed signing time" }
        ],
        trustGaps: [{ id: "revocation", title: "Revocation status", detail: "No CRL / OCSP checks." }],
        warnings: ["synthetic verification warning"]
      },
      signerCount: 1,
      certificateCount: 2,
      signers: [{
        issuer: "CN=Test Issuer",
        serialNumber: "1234",
        digestAlgorithmName: "sha256",
        signatureAlgorithmName: "rsaEncryption",
        signingTime: "2024-01-01T00:00:00Z"
      }],
      certificates: [
        { subject: "CN=Test Subject", issuer: "CN=Test Issuer", serialNumber: "1234", notBefore: "2024-01-01T00:00:00Z", notAfter: "2025-01-01T00:00:00Z" },
        { subject: "CN=Test Timestamp", issuer: "CN=Test Issuer", serialNumber: "5678", notBefore: "2024-01-01T00:00:00Z", notAfter: "2026-01-01T00:00:00Z" }
      ]
    }
  }]
};

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
      fileDigestAlgorithmName: "sha256",
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
  assert.ok(html.includes("WIN_CERTIFICATE record #1"));
  assert.ok(html.includes("Type 0xf00d"));
  assert.ok(html.includes("1.2.3.4"));
  assert.ok(!html.includes("Show certificates"));
  assert.ok(html.includes("sha256"));
  assert.ok(html.includes("truncated"));
  assert.ok(html.includes("Certificate tree"));
  assert.ok(html.includes("Authenticode"));
  assert.ok(html.includes("Structural warnings"));
  assert.ok(html.includes("Length field does not match directory entry size."));
});

void test("renderSecurity includes expanded Authenticode details", () => {
  const out: string[] = [];
  renderSecurity(EXPANDED_AUTHENTICODE_SECURITY, out);
  const html = out.join("");
  assert.ok(html.includes("Certificate tree"));
  assert.ok(html.includes("Authenticode"));
  assert.ok(html.includes("Countersignature 1"));
  assert.ok(html.includes("Trust limitations"));
  assert.ok(html.includes("peSecurityTreeBadge--pass"));
  assert.ok(html.includes("peSecurityTreeBadge--unknown"));
  assert.ok(html.includes("Digest"));
  assert.ok(html.includes("Sig"));
  assert.ok(html.includes("Revocation status"));
  assert.ok(html.includes("PKCS#7"));
  assert.ok(html.includes("SPC_INDIRECT_DATA"));
  assert.ok(html.includes("sha256"));
  assert.ok(html.includes("Claimed signing time"));
  assert.ok(html.includes("Subject"));
  assert.ok(html.includes("synthetic verification warning"));
});

void test("renderSecurity renders count without certificate table", () => {
  const security: Parameters<typeof renderSecurity>[0] = { count: 0, certs: [] };
  const out: string[] = [];
  renderSecurity(security, out);
  const html = out.join("");
  assert.ok(html.includes("Certificate records"));
  assert.ok(html.includes(
    "Number of parsed WIN_CERTIFICATE records; this does not establish signature validity."
  ));
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

void test("renderSecurity keeps Authenticode root unknown when signer verification is unknown", () => {
  const security: Parameters<typeof renderSecurity>[0] = {
    count: 1,
    certs: [{
      offset: 0,
      length: 32,
      availableBytes: 32,
      revision: 0x0200,
      revisionName: "Revision 2.0",
      certificateType: 0x0002,
      typeName: "PKCS#7 SignedData (Authenticode)",
      authenticode: {
        format: "pkcs7" as const,
        fileDigest: "deadbeef",
        verification: {
          checks: [
            {
              id: "file-digest-match",
              status: "pass" as const,
              title: "Embedded file digest matches the computed PE Authenticode digest"
            },
            {
              id: "Signer 1-signature",
              status: "unknown" as const,
              title: "Signer 1: CMS signature verifies",
              detail: "Unsupported signature algorithm"
            }
          ]
        },
        signerCount: 1
      }
    }]
  };
  const out: string[] = [];
  renderSecurity(security, out);
  const html = out.join("");
  assert.match(html, /Authenticode[\s\S]*?peSecurityTreeNode--unknown/);
  assert.ok(html.includes("Unsupported signature algorithm"));
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
      verification: {
        fileDigestMatches: false,
        checks: [
          {
            id: "file-digest-match",
            status: "fail" as const,
            title: "Embedded file digest matches the computed PE Authenticode digest",
            detail: "Embedded deadbeef, computed 0011"
          }
        ]
      },
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
  assert.ok(html.includes("peSecurityTreeBadge--fail"));
  assert.ok(html.includes("Digest"));
  assert.ok(html.includes("Embedded deadbeef, computed 0011"));
});
