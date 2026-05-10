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

void test("renderAuthenticodeTree treats current expiry as informational on timestamped paths", () => {
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
        { subject: "CN=Leaf", issuer: "CN=Issuer" },
        { subject: "CN=Issuer", issuer: "CN=Issuer" }
      ],
      verification: {
        checks: [
          {
            id: "Signer 1-certificate-1-timestamp time-validity",
            status: "pass",
            title: "Signer 1: certificate 1 was valid at timestamp time",
            detail: "2024-01-15T00:00:00Z: 2024-01-01T00:00:00Z -> 2024-02-01T00:00:00Z"
          },
          {
            id: "Signer 1-certificate-2-current-validity",
            status: "fail",
            title: "Signer 1: certificate 2 is currently valid",
            detail: "Current time: 2023-01-01T00:00:00Z -> 2024-02-01T00:00:00Z"
          }
        ],
        signerVerifications: [
          {
            index: 0,
            signerCertificateIndex: 0,
            certificatePathIndexes: [0, 1]
          }
        ]
      }
    }
  });

  assert.strictEqual(
    getNodeClassForTitle(html, "Certificate &#8470;2: CN=Issuer"),
    "peSecurityTreeNode peSecurityTreeNode--info"
  );
});

void test("renderAuthenticodeTree keeps current expiry failing without a timestamp reference", () => {
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
      certificates: [{ subject: "CN=Expired Leaf", issuer: "CN=Expired Leaf" }],
      verification: {
        checks: [
          {
            id: "Signer 1-certificate-1-current-validity",
            status: "fail",
            title: "Signer 1: certificate 1 is currently valid",
            detail: "Current time: 2023-01-01T00:00:00Z -> 2024-02-01T00:00:00Z"
          }
        ],
        signerVerifications: [
          {
            index: 0,
            signerCertificateIndex: 0,
            certificatePathIndexes: [0]
          }
        ]
      }
    }
  });

  assert.strictEqual(
    getNodeClassForTitle(html, "Certificate &#8470;1: CN=Expired Leaf"),
    "peSecurityTreeNode peSecurityTreeNode--fail"
  );
});
