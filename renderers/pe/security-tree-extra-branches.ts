"use strict";

import type {
  AuthenticodeInfo,
  AuthenticodeTrustGap
} from "../../analyzers/pe/authenticode/index.js";
import {
  collectConnectedCertificateIndexes,
  createCertificateTrustBadge,
  getCertificate,
  getCertificateTrust
} from "./security-tree-checks.js";
import {
  formatCertificateTitle,
  formatDistinguishedNameTooltip
} from "./security-tree-dn.js";
import {
  createInfoBadge,
  createRoleBadge,
  createStatusBadge,
  filterBadges,
  renderCertificateDownloadButton,
  renderTreeMeta,
  renderTreeNode
} from "./security-tree-markup.js";

const TRUST_GAP_LABELS: Record<string, string> = {
  "trust-anchor": "Store",
  revocation: "Revoke",
  "missing-intermediates": "AIA",
  "platform-policy": "Policy",
  "timestamp-trust": "TSA"
};

export const renderAdditionalCertificatesNode = (auth: AuthenticodeInfo): string => {
  const connected = collectConnectedCertificateIndexes(auth);
  const additionalIndexes = (auth.certificates ?? [])
    .map((_, index) => index)
    .filter(index => !connected.has(index));
  if (!additionalIndexes.length) return "";
  return renderTreeNode(
    "Detached embedded certificates",
    [
      createRoleBadge("Embedded", "certificate"),
      createInfoBadge(
        `${additionalIndexes.length} detached`,
        "Embedded certificates that are not connected to any signer or issuer relation."
      )
    ],
    [],
    additionalIndexes
      .map(index =>
        renderTreeNode(
          formatCertificateTitle(index, getCertificate(auth.certificates, index)?.subject),
          filterBadges([
            createRoleBadge(
              getCertificate(auth.certificates, index)?.subject ===
                getCertificate(auth.certificates, index)?.issuer
                ? "Root"
                : "Embedded only",
              "certificate"
            ),
            createCertificateTrustBadge(auth, index)
          ]),
          [
            renderTreeMeta("Issuer", getCertificate(auth.certificates, index)?.issuer),
            renderTreeMeta("Serial", getCertificate(auth.certificates, index)?.serialNumber),
            renderTreeMeta("SHA-1", getCertificateTrust(auth, index)?.sha1Thumbprint),
            renderTreeMeta(
              "Validity",
              getCertificate(auth.certificates, index)?.notBefore ||
                getCertificate(auth.certificates, index)?.notAfter
                ? `${getCertificate(auth.certificates, index)?.notBefore || "?"} -> ${
                    getCertificate(auth.certificates, index)?.notAfter || "?"
                  }`
                : undefined
            )
          ],
          undefined,
          formatDistinguishedNameTooltip(getCertificate(auth.certificates, index)?.subject),
          renderCertificateDownloadButton(
            getCertificate(auth.certificates, index)?.derBase64 ??
              getCertificateTrust(auth, index)?.derBase64,
            `authenticode-certificate-${index + 1}.cer`,
            `Download embedded certificate ${index + 1}`
          )
        )
      )
      .join("")
  );
};

export const renderTrustGapsNode = (gaps: AuthenticodeTrustGap[] | undefined): string =>
  gaps?.length
    ? renderTreeNode(
        "Not checked for trust",
        [
          createRoleBadge("Trust", "certificate"),
          ...gaps.map(gap =>
            createStatusBadge(
              TRUST_GAP_LABELS[gap.id] || gap.title,
              "unknown",
              `${gap.title}: ${gap.detail}`
            )
          )
        ],
        []
      )
    : "";

export const renderWarningsNode = (title: string, warnings: string[] | undefined): string =>
  warnings?.length
    ? renderTreeNode(
        title,
        [
          createRoleBadge("Warn", "certificate"),
          createStatusBadge(`${warnings.length} note${warnings.length === 1 ? "" : "s"}`, "unknown", title)
        ],
        warnings.map((warning, index) => renderTreeMeta(`Note ${index + 1}`, warning))
      )
    : "";
