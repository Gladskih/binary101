"use strict";

import type { AuthenticodeCheckStatus } from "../../analyzers/pe/authenticode/index.js";
import { escapeHtml } from "../../html-utils.js";

export type TreeBadgeStatus = AuthenticodeCheckStatus | "info";

export interface TreeBadge {
  label: string;
  status: TreeBadgeStatus;
  detail?: string;
  modifier?: string;
}

const BADGE_ICONS: Record<TreeBadgeStatus, string> = {
  pass: "&#10003;",
  fail: "&#10007;",
  unknown: "&#9888;",
  info: ""
};

export const formatCheckDetail = (title: string, detail: string | undefined): string =>
  detail ? `${title}: ${detail}` : title;

export const createRoleBadge = (
  label: string,
  modifier?: string,
  detail?: string
): TreeBadge => ({
  label,
  status: "info",
  ...(detail ? { detail } : {}),
  ...(modifier ? { modifier } : {})
});

export const createInfoBadge = (label: string, detail?: string): TreeBadge => ({
  label,
  status: "info",
  ...(detail ? { detail } : {})
});

export const createStatusBadge = (
  label: string,
  status: AuthenticodeCheckStatus,
  detail: string
): TreeBadge => ({
  label,
  status,
  detail
});

export const filterBadges = (badges: Array<TreeBadge | undefined>): TreeBadge[] =>
  badges.filter((badge): badge is TreeBadge => badge != null);

const getNodeStatus = (
  badges: TreeBadge[],
  inheritedStatus: TreeBadgeStatus | undefined
): TreeBadgeStatus => {
  const statuses = [
    ...(inheritedStatus ? [inheritedStatus] : []),
    ...badges.map(badge => badge.status)
  ];
  if (statuses.includes("fail")) return "fail";
  if (statuses.includes("unknown")) return "unknown";
  if (statuses.includes("pass")) return "pass";
  return "info";
};

const renderTreeBadge = (badge: TreeBadge): string =>
  `<span class="peSecurityTreeBadge peSecurityTreeBadge--${badge.status}${
    badge.modifier ? ` peSecurityTreeBadge--${badge.modifier}` : ""
  }"${badge.detail ? ` title="${escapeHtml(badge.detail)}"` : ""}>${
    BADGE_ICONS[badge.status]
      ? `<span class="peSecurityTreeBadgeIcon" aria-hidden="true">${BADGE_ICONS[badge.status]}</span>`
      : ""
  }<span>${escapeHtml(badge.label)}</span></span>`;

export const renderTreeMeta = (label: string, value: string | undefined): string =>
  value
    ? `<div class="smallNote peSecurityTreeMeta"><span>${escapeHtml(label)}:</span> ${escapeHtml(value)}</div>`
    : "";

export const renderCertificateDownloadButton = (
  derBase64: string | undefined,
  filename: string,
  label: string
): string =>
  derBase64
    ? `<button type="button" class="peSecurityTreeDownloadButton" data-certificate-download ` +
      `data-certificate-der-base64="${escapeHtml(derBase64)}" data-certificate-filename="${escapeHtml(filename)}" ` +
      `aria-label="${escapeHtml(label)}" title="${escapeHtml(label)}">` +
      `<svg aria-hidden="true" viewBox="0 0 16 16" width="14" height="14" fill="none" ` +
      `stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">` +
      `<path d="M8 2.5v7"></path><path d="M5 6.8 8 9.8l3-3"></path>` +
      `<path d="M3 12.5h10"></path>` +
      `</svg></button>`
    : "";

export const renderTreeNode = (
  title: string,
  badges: TreeBadge[],
  meta: string[],
  children?: string,
  titleDetail?: string,
  actions = "",
  inheritedStatus?: TreeBadgeStatus
): string => (
  `<li class="peSecurityTreeItem">` +
  `<div class="peSecurityTreeNode peSecurityTreeNode--${getNodeStatus(badges, inheritedStatus)}">` +
  `<div class="peSecurityTreeTitleRow">` +
  `<div class="peSecurityTreeTitle"${titleDetail ? ` title="${escapeHtml(titleDetail)}"` : ""}>${escapeHtml(title)}</div>` +
  actions +
  `</div><div class="peSecurityTreeBadges">${badges.map(renderTreeBadge).join("")}</div>` +
  `${meta.join("")}</div>` +
  (children ? `<ul class="peSecurityTree">${children}</ul>` : "") +
  `</li>`
);
